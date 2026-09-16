#pragma once

#include "native_bridge.h"

// ── RpcStdinReader ────────────────────────────────────────────────────────
//
// Background thread reading stdin line-by-line; every line that starts
// with `NRR_IPC_RESPONSE:` is forwarded to the bridge via
// `QMetaObject::invokeMethod(... Qt::QueuedConnection)`. Other lines
// are ignored (the protocol only flows in one direction on stdin).
//
// The reader uses `std::cin` instead of QFile/QSocketNotifier because
// stdin on Windows is not a Qt-friendly handle — `getline` on a
// background thread is the simplest portable approach.
//
// Shutdown:
//   `std::getline(std::cin, ...)` is a BLOCKING read on the OS handle;
//   simply destroying the QThread doesn't unblock it. On the
//   `QCoreApplication::aboutToQuit` signal the host calls
//   `requestStopAndCloseStdin()` which:
//     1. sets the `stop_` atomic so the loop won't re-enter `getline`
//        even if a stray byte arrives during the close window;
//     2. closes `STD_INPUT_HANDLE` via Win32, which fails the kernel-
//        side ReadFile → `std::cin` enters EOF state → `getline`
//        returns false → loop exits cleanly.
//   `main()` then calls `wait()` before letting the QThread destructor
//   run, eliminating the "QThread: Destroyed while thread is still
//   running" qFatal diagnostic that fires in Qt6 debug builds.
class RpcStdinReader : public QThread {
    Q_OBJECT
public:
    explicit RpcStdinReader(NrrNativeBridge *bridge, QObject *parent = nullptr)
        : QThread(parent), bridge_(bridge) {
        setObjectName(QStringLiteral("nrr-rpc-stdin-reader"));
    }

    /// Called from `QCoreApplication::aboutToQuit`
    /// on the GUI thread. The reader is blocked inside `std::getline`
    /// which calls `ReadFile` on STD_INPUT_HANDLE. On Windows simply
    /// closing the OS handle is NOT always enough: the MSVC CRT holds
    /// its own duplicated handle wrapping fd 0 inside `std::cin`'s
    /// streambuf, and `ReadFile` may still be parked in the kernel.
    /// The robust unblock is `CancelSynchronousIo` on the reader's
    /// thread handle. We belt-and-brace it with `_close(0)` (kills the
    /// CRT fd) and `CloseHandle(GetStdHandle(...))` (kills the
    /// inherited pipe handle) so any of three layers wakes the read.
    /// On the main GUI this almost always wakes via real RPC traffic
    /// before shutdown; the tray rarely sees stdin traffic, so without
    /// this cancellation the reader thread would hang in `getline`
    /// until the destructor fires a `QThread: Destroyed while thread
    /// is still running` qFatal.
    void requestStopAndCloseStdin() {
        // Called from `aboutToQuit` AND from the shutdown path, and everything
        // below closes handles. A second pass would close descriptors the CRT
        // may have handed to something else by then, so the first pass is the
        // only one that does anything.
        if (stdinClosed_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        stop_.store(true, std::memory_order_release);
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
        // Closing fd 0 invalidates the CRT-side stream `std::cin` sits on;
        // the next `ReadFile` (or the in-flight one, once Cancel returns)
        // sees EBADF and `getline` enters fail state.
        ::_close(0);
        HANDLE h = ::GetStdHandle(STD_INPUT_HANDLE);
        if (h != nullptr && h != INVALID_HANDLE_VALUE) {
            ::CloseHandle(h);
        }
#else
        std::fclose(stdin);
#endif
    }

protected:
    void run() override {
#ifdef Q_OS_WIN
        readerThreadId_.store(::GetCurrentThreadId(), std::memory_order_release);
#endif
        std::string line;
        while (!stop_.load(std::memory_order_acquire)
               && std::getline(std::cin, line)) {
            if (line.empty()) {
                continue;
            }
            const QString qline = QString::fromStdString(line);
            if (qline.startsWith(QStringLiteral("NRR_IPC_RESPONSE:"))) {
                // Bridge receives the response on its owning thread (GUI).
                QMetaObject::invokeMethod(
                    bridge_, "deliverRpcResponse", Qt::QueuedConnection,
                    Q_ARG(QString, qline));
                bridge_->incrementRpcResponseCount();
                continue;
            }
            if (qline.startsWith(QStringLiteral("NRR_IPC_PUSH:"))) {
                // Push frame. Routed via deliverPushEvent.
                QMetaObject::invokeMethod(
                    bridge_, "deliverPushEvent", Qt::QueuedConnection,
                    Q_ARG(QString, qline));
                continue;
            }
        }
    }

private:
    NrrNativeBridge *bridge_ = nullptr;
    std::atomic<bool> stop_{false};
    std::atomic<bool> stdinClosed_{false};
#ifdef Q_OS_WIN
    // Win32 thread id captured at the start of `run()`. Used by
    // `requestStopAndCloseStdin` to call `CancelSynchronousIo` against
    // the reader's own thread handle. DWORD; 0 means "not yet running".
    std::atomic<DWORD> readerThreadId_{0};
#endif
};
