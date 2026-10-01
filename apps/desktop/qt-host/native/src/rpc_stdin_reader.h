#pragma once

#include "native_bridge.h"

#ifndef Q_OS_WIN
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

// ── RpcStdinReader ────────────────────────────────────────────────────────
//
// Background thread reading the launcher's lines from stdin. Lines starting
// with `NRR_IPC_RESPONSE:` or `NRR_IPC_PUSH:` are forwarded to the bridge on
// its own thread; anything else is ignored.
//
// Stopping. A thread parked in a blocking read wakes only when that read is
// made to return, and a QThread destroyed while running is a qFatal:
//   - Windows reads with `getline` on `std::cin`; `requestStop` cancels the
//     pending `ReadFile` and closes both the CRT fd and the Win32 handle — no
//     single one of the three is reliably enough.
//   - POSIX: closing stdin does not wake a thread already inside `read(0)`, so
//     the reader polls fd 0 together with a self-pipe that `requestStop`
//     writes to.
//
// The end of stdin without a stop means the launcher is gone: nothing answers
// RPC or persists preferences any more, and its single-instance lock is free
// for a second window. `rpcChannelClosed` lets the host quit instead.
class RpcStdinReader : public QThread {
    Q_OBJECT
public:
    explicit RpcStdinReader(NrrNativeBridge *bridge, QObject *parent = nullptr)
        : QThread(parent), bridge_(bridge) {
        setObjectName(QStringLiteral("nrr-rpc-stdin-reader"));
#ifndef Q_OS_WIN
        openWakePipe();
#endif
    }

    ~RpcStdinReader() override {
#ifndef Q_OS_WIN
        // A reader that outlived its wait may still be polling these.
        if (!isRunning()) {
            for (int &fd : wakePipe_) {
                if (fd >= 0) {
                    ::close(fd);
                    fd = -1;
                }
            }
        }
#endif
    }

    /// Wakes the reader and makes it exit without `rpcChannelClosed`. Safe to
    /// call from any thread, any number of times; only the first call acts.
    void requestStop() {
        // The Windows branch closes descriptors; a second pass would close ones
        // the CRT may have handed to something else by then.
        if (stop_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
#ifdef Q_OS_WIN
        DWORD tid = readerThreadId_.load(std::memory_order_acquire);
        if (tid != 0) {
            HANDLE threadHandle = ::OpenThread(THREAD_TERMINATE | THREAD_SUSPEND_RESUME
                                                   | 0x0001 /* THREAD_QUERY_INFORMATION */,
                                               FALSE, tid);
            if (threadHandle != nullptr) {
                ::CancelSynchronousIo(threadHandle);
                ::CloseHandle(threadHandle);
            }
        }
        ::_close(0);
        HANDLE h = ::GetStdHandle(STD_INPUT_HANDLE);
        if (h != nullptr && h != INVALID_HANDLE_VALUE) {
            ::CloseHandle(h);
        }
#else
        if (wakePipe_[1] >= 0) {
            const char byte = 1;
            ssize_t written = 0;
            do {
                written = ::write(wakePipe_[1], &byte, 1);
            } while (written < 0 && errno == EINTR);
        }
#endif
    }

signals:
    /// Stdin ended with no stop requested: the launcher is gone. Emitted on the
    /// reader thread.
    void rpcChannelClosed();

protected:
    void run() override {
        // Only a pipe is the launcher's channel. A host started by hand has a
        // console or nothing on stdin, and its end says nothing about a
        // launcher.
        const bool fromLauncher = stdinIsPipe();
#ifdef Q_OS_WIN
        readerThreadId_.store(::GetCurrentThreadId(), std::memory_order_release);
        std::string line;
        while (!stop_.load(std::memory_order_acquire)
               && std::getline(std::cin, line)) {
            handleLine(line);
        }
#else
        readLinesFromStdin();
#endif
        if (fromLauncher && !stop_.load(std::memory_order_acquire)) {
            emit rpcChannelClosed();
        }
    }

private:
    void handleLine(const std::string &line) {
        if (line.empty()) {
            return;
        }
        const QString qline = QString::fromStdString(line);
        if (qline.startsWith(QStringLiteral("NRR_IPC_RESPONSE:"))) {
            QMetaObject::invokeMethod(
                bridge_, "deliverRpcResponse", Qt::QueuedConnection,
                Q_ARG(QString, qline));
            bridge_->incrementRpcResponseCount();
            return;
        }
        if (qline.startsWith(QStringLiteral("NRR_IPC_PUSH:"))) {
            QMetaObject::invokeMethod(
                bridge_, "deliverPushEvent", Qt::QueuedConnection,
                Q_ARG(QString, qline));
        }
    }

    static bool stdinIsPipe() {
#ifdef Q_OS_WIN
        HANDLE h = ::GetStdHandle(STD_INPUT_HANDLE);
        return h != nullptr && h != INVALID_HANDLE_VALUE
               && ::GetFileType(h) == FILE_TYPE_PIPE;
#else
        struct stat st {};
        return ::fstat(0, &st) == 0 && (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode));
#endif
    }

#ifndef Q_OS_WIN
    // Without the pipe the reader still stops, a poll interval late.
    static constexpr int kPollWithoutWakeMs = 250;

    void openWakePipe() {
        int fds[2] = {-1, -1};
        if (::pipe(fds) != 0) {
            return;
        }
        for (int fd : fds) {
            ::fcntl(fd, F_SETFD, FD_CLOEXEC);
        }
        // Never block `requestStop`, which runs on the GUI thread.
        ::fcntl(fds[1], F_SETFL, ::fcntl(fds[1], F_GETFL) | O_NONBLOCK);
        wakePipe_[0] = fds[0];
        wakePipe_[1] = fds[1];
    }

    void readLinesFromStdin() {
        std::string pending;
        char buffer[4096];
        const bool canWake = wakePipe_[0] >= 0;
        while (!stop_.load(std::memory_order_acquire)) {
            pollfd fds[2] = {{0, POLLIN, 0}, {wakePipe_[0], POLLIN, 0}};
            const int ready = ::poll(fds, canWake ? 2 : 1, canWake ? -1 : kPollWithoutWakeMs);
            if (ready < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return;
            }
            if (ready == 0 || (canWake && fds[1].revents != 0)) {
                continue; // the loop condition sees the stop
            }
            if ((fds[0].revents & POLLNVAL) != 0) {
                return;
            }
            if ((fds[0].revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
                continue;
            }
            const ssize_t count = ::read(0, buffer, sizeof buffer);
            if (count < 0) {
                if (errno == EINTR || errno == EAGAIN) {
                    continue;
                }
                return;
            }
            if (count == 0) {
                break;
            }
            pending.append(buffer, static_cast<size_t>(count));
            size_t start = 0;
            for (size_t end = pending.find('\n'); end != std::string::npos;
                 end = pending.find('\n', start)) {
                handleLine(pending.substr(start, end - start));
                start = end + 1;
            }
            pending.erase(0, start);
        }
        // `getline` hands over an unterminated last line too.
        if (!stop_.load(std::memory_order_acquire)) {
            handleLine(pending);
        }
    }

    int wakePipe_[2] = {-1, -1};
#endif

    NrrNativeBridge *bridge_ = nullptr;
    std::atomic<bool> stop_{false};
#ifdef Q_OS_WIN
    // Captured at the start of `run()` so `requestStop` can cancel the reader's
    // own pending read; 0 = not running yet.
    std::atomic<DWORD> readerThreadId_{0};
#endif
};
