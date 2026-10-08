#pragma once

#include "native_bridge.h"

// ── NrrServiceController ─────────────────────────────────────────────────
//
// Q_OBJECT bridge for the Windows Service Control Manager. Wraps the
// SCM read API for status queries and the elevated `runas` flow for
// install/uninstall/start/stop. All elevated operations are dispatched
// to a worker QThread so the GUI thread never blocks on
// `ShellExecuteExW` + `WaitForSingleObject(30 s)`.
//
// Status enum mirrors `SERVICE_STATUS::dwCurrentState`:
//   - Unknown (SCM error / before first query)
//   - NotInstalled (`OpenServiceW` returned `ERROR_SERVICE_DOES_NOT_EXIST`)
//   - Stopped / StartPending / Running / StopPending (direct mapping)
//
// Signals:
//   - statusChanged: emitted whenever `refreshStatus()` observes a
//     transition. QML uses it for badge + Timer-driven polling.
//   - operationCompleted(operation, success, errorMessage, errorCode): emitted
//     at the end of every async install/uninstall/start/stop. `errorCode` is
//     the launcher's refusal slug when it gave one, so QML can word it.
//   - uacDeclined(operation): emitted when `ShellExecuteExW` returned
//     `FALSE` with `GetLastError() == ERROR_CANCELLED` (1223). QML
//     uses this to record the decline in `prefs.serviceInstallUacDeclined*`
//     and downgrade re-prompting to a passive banner.
//
// The service binary is the one beside this host, or the path the launcher
// hands over in `--nrr-service-exe=` (see the constructor).

// How long a direct elevated run may take once its prompt is answered.
inline constexpr int kElevatedRunTimeoutMs = 30000;

// How long the GUI waits for the launcher to answer a broker-routed action.
// Must exceed the broker's own bound for it (`client_answer_timeout` for
// `broker.service-control`: settle 1.5 s + child budget 90 s + margin 5 s),
// or a slow restart that succeeds reads as a failure; the direct run's
// allowance on top covers the prompt and the RPC hop. A Rust test pins it.
inline constexpr int kBrokerServiceControlTimeoutMs = 96500 + kElevatedRunTimeoutMs;

inline QString nrrServiceOperationTimedOut() {
    return QStringLiteral("Timed out waiting for service operation");
}

class NrrServiceWorker : public QObject {
    Q_OBJECT
public:
    explicit NrrServiceWorker(QObject *parent = nullptr) : QObject(parent) {}

public slots:
    /// Invokes `<servicePath> <command>` via `ShellExecuteExW` with the
    /// `runas` verb, waits up to `kElevatedRunTimeoutMs`, and emits
    /// `result(operation, success, errorMessage)` on the controller's
    /// signal slot.
    void runElevated(const QString &operation,
                     const QString &servicePath,
                     const QString &command) {
#ifndef Q_OS_WIN
        // Elsewhere the launcher carries the action out (`dispatch` routes it
        // there); a host started without one has no way to, and says so
        // rather than appear to do nothing.
        (void) servicePath;
        (void) command;
        emit result(operation, false,
                    QStringLiteral("Service control needs the app's launcher; "
                                   "start the app normally, or use the command line."));
#else
        SHELLEXECUTEINFOW sei{};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        // Already-elevated GUI: launch with the default verb so the child
        // inherits our elevated token silently. Non-elevated GUI: use the
        // `runas` verb, which raises the UAC consent prompt.
        sei.lpVerb = nrrProcessIsElevated() ? nullptr : L"runas";
        const std::wstring exe = servicePath.toStdWString();
        const std::wstring arg = command.toStdWString();
        sei.lpFile = exe.c_str();
        sei.lpParameters = arg.c_str();
        sei.nShow = SW_HIDE;

        const BOOL ok = ShellExecuteExW(&sei);
        if (!ok) {
            const DWORD lastError = GetLastError();
            if (lastError == ERROR_CANCELLED) {
                emit uacDeclined(operation);
                return;
            }
            emit result(operation, false,
                        QStringLiteral("ShellExecuteExW failed: %1").arg(lastError));
            return;
        }

        const DWORD wait = WaitForSingleObject(sei.hProcess, kElevatedRunTimeoutMs);
        if (wait != WAIT_OBJECT_0) {
            CloseHandle(sei.hProcess);
            emit result(operation, false, nrrServiceOperationTimedOut());
            return;
        }
        DWORD exitCode = 1;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);
        if (exitCode == 0) {
            emit result(operation, true, QString());
        } else {
            emit result(operation, false,
                        QStringLiteral("Service binary exited with code %1").arg(exitCode));
        }
#endif
    }

signals:
    void result(QString operation, bool success, QString errorMessage);
    void uacDeclined(QString operation);
};

class NrrServiceController : public QObject {
    Q_OBJECT
    Q_PROPERTY(int status READ status NOTIFY statusChanged)
    Q_PROPERTY(QString statusReason READ statusReason NOTIFY statusChanged)
    // Progress state for install/start/stop/uninstall/restart.
    // `busy` stays true across chained legs (install→start, restart=stop→start)
    // so the GUI can keep a single progress indicator up for the whole flow;
    // `activeOperation` names the leg currently in flight.
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(QString activeOperation READ activeOperation NOTIFY busyChanged)
    // Answered from a cache; `refreshStartMode()` refills it off the GUI thread.
    Q_PROPERTY(QString startMode READ startMode NOTIFY startModeChanged)
public:
    enum Status {
        Unknown = 0,
        NotInstalled = 1,
        Stopped = 2,
        StartPending = 3,
        Running = 4,
        StopPending = 5,
    };
    Q_ENUM(Status)

    explicit NrrServiceController(const QString &applicationDir,
                                  const QString &handedOverServiceExe,
                                  QObject *parent = nullptr)
        : QObject(parent) {
        // Only the sibling: this path ends at `ShellExecuteExW` with an admin
        // token, and a search climbing from an installed GUI reaches the drive
        // root, where any authenticated user can create a directory. A cargo
        // build, whose host is not a sibling, gets the path from the launcher.
        const QString sibling =
            QDir(applicationDir).filePath(serviceBinaryName());
        if (QFileInfo::exists(sibling)) {
            servicePath_ = QDir::cleanPath(sibling);
        }
        // Compiled into every build (the host ships `RelWithDebInfo`, so an
        // `NDEBUG` gate would drop it). Whoever forges the spawning command
        // line already picks the binaries; the file must exist and carry the
        // service's role name.
        if (servicePath_.isEmpty() && !handedOverServiceExe.isEmpty()) {
            const QString handed = normalizeLocalPath(handedOverServiceExe);
            const bool named =
                QFileInfo(handed).fileName().compare(serviceBinaryName(),
                                                     Qt::CaseInsensitive) == 0;
            if (named && QFileInfo::exists(handed)) {
                servicePath_ = QDir::cleanPath(handed);
            } else {
                qWarning().noquote()
                    << "NRR_SERVICE_EXE_REFUSED" << handed
                    << "(exists=" << QFileInfo::exists(handed) << "named=" << named << ")";
            }
        }

        // Worker thread for elevated operations.
        worker_ = new NrrServiceWorker();
        worker_->moveToThread(&workerThread_);
        connect(&workerThread_, &QThread::finished, worker_, &QObject::deleteLater);
        connect(worker_, &NrrServiceWorker::result,
                this, &NrrServiceController::onWorkerResult,
                Qt::QueuedConnection);
        connect(worker_, &NrrServiceWorker::uacDeclined,
                this, &NrrServiceController::onWorkerUacDeclined,
                Qt::QueuedConnection);
        workerThread_.start();

        pendingPollTimer_.setSingleShot(true);
        connect(&pendingPollTimer_, &QTimer::timeout,
                this, &NrrServiceController::refreshStatus);

        refreshStatus();
    }

    ~NrrServiceController() override {
        // A query still running must not report into a half-destroyed controller.
        if (statusProc_ != nullptr) {
            disconnect(statusProc_, nullptr, this, nullptr);
        }
        workerThread_.quit();
        workerThread_.wait();
    }

    int status() const { return static_cast<int>(status_); }
    QString statusReason() const { return statusReason_; }
    bool busy() const { return busy_; }
    QString activeOperation() const { return activeOperation_; }

    Q_INVOKABLE void refreshStatus() {
#ifndef Q_OS_WIN
        querySystemdStatus();
#else
        QString reason;
        const Status next = queryStatus(&reason);
        applyStatus(next, reason);
#endif
    }

    Q_INVOKABLE QString servicePath() const { return servicePath_; }

    Q_INVOKABLE bool isCurrentProcessElevated() const {
        return nrrProcessIsElevated();
    }

    /// Wire the RPC bridge so a non-elevated
    /// GUI can route service control through the session elevation broker
    /// (one UAC per session) instead of a per-action `ShellExecute runas`.
    /// Set once at startup in `main()`. Null ⇒ fall back to direct elevation.
    void setBridge(NrrNativeBridge *bridge) { bridge_ = bridge; }

    Q_INVOKABLE void installService()   { dispatch(QStringLiteral("install"),   QStringLiteral("install")); }
    Q_INVOKABLE void uninstallService() { dispatch(QStringLiteral("uninstall"), QStringLiteral("uninstall")); }
    Q_INVOKABLE void startService()     { dispatch(QStringLiteral("start"),     QStringLiteral("start")); }
    Q_INVOKABLE void stopService()      { dispatch(QStringLiteral("stop"),      QStringLiteral("stop")); }

    Q_INVOKABLE void restartService() {
        // One elevated process performs stop→start (the service `restart`
        // subcommand) so the user sees a SINGLE UAC prompt instead of two
        // (one for stop, one for start).
        dispatch(QStringLiteral("restart"), QStringLiteral("restart"));
    }

    /// Re-point the registration at the service binary shipped with THIS copy
    /// of the app, then start it.
    ///
    /// One elevated process does remove→register→start, so the swap costs a
    /// single UAC prompt. The path is never passed as an argument: the broker
    /// runs one whitelisted token, and the binary registers itself.
    Q_INVOKABLE void reinstallService() {
        dispatch(QStringLiteral("reinstall"), QStringLiteral("reinstall"));
    }

    /// Emergency network recovery: run the service binary's own teardown of the
    /// state it applied (packet filters, the DNS redirect, our routes).
    ///
    /// Deliberately the SAME verb the console drives, through the same elevated
    /// broker: the program that applied the state is the only one that knows all
    /// of it, and a second implementation would be a copy that drifts — found
    /// out, if ever, during the outage it exists to fix. The confirmation is
    /// QML's job; by the time this is called the user has already agreed.
    Q_INVOKABLE void resetNetwork() {
        dispatch(QStringLiteral("cleanup"), QStringLiteral("cleanup"));
    }

    /// Switch the service start mode (admin-opt-in).
    /// `mode` is the wire slug: "with-windows" (= start with Windows /
    /// SERVICE_AUTO_START) or "on-app-launch" (= start when the app opens /
    /// SERVICE_DEMAND_START + the targeted SERVICE_START grant). Routed through
    /// the same elevated broker path as install/uninstall; the single-token verb
    /// the service understands is `set-start-auto` / `set-start-demand`.
    Q_INVOKABLE void setServiceStartMode(const QString &mode) {
        const bool demand = (mode == QStringLiteral("on-app-launch")
                             || mode == QStringLiteral("demand"));
        const QString verb = demand ? QStringLiteral("set-start-demand")
                                    : QStringLiteral("set-start-auto");
        dispatch(verb, verb);
    }

    /// Last known start mode: the slug the UNELEVATED `query-start-mode` verb
    /// printed ("with-windows" / "on-app-launch"), or empty when the service is
    /// not installed, unreadable, or has not been asked yet.
    QString startMode() const { return startMode_; }

    /// Ask the service binary for its start mode, WITHOUT blocking.
    ///
    /// Spawning a process and waiting for it is not something a GUI thread may
    /// do: the wait was budgeted at three seconds, and every one of them is a
    /// frozen window — on exactly the machine where the service is unwell and
    /// the binary is slow to answer. The answer arrives through
    /// `startModeChanged` instead; readers bind to `startMode`.
    ///
    /// Re-entrant by design: a refresh already in flight is left to finish
    /// rather than restarted, so a burst of requests costs one process.
    Q_INVOKABLE void refreshStartMode() {
        if (servicePath_.isEmpty() || startModeProc_ != nullptr) {
            return;
        }
        auto *proc = new QProcess(this);
        startModeProc_ = proc;
#ifdef Q_OS_WIN
        // The service binary is console-subsystem; suppress the conhost flash
        // (CREATE_NO_WINDOW, mirroring the broker's exec).
        proc->setCreateProcessArgumentsModifier(
            [](QProcess::CreateProcessArguments *args) {
                args->flags |= 0x08000000; // CREATE_NO_WINDOW
            });
#endif
        connect(proc, &QProcess::finished, this,
                [this, proc](int exitCode, QProcess::ExitStatus status) {
                    QString slug;
                    if (status == QProcess::NormalExit && exitCode == 0) {
                        slug = QString::fromUtf8(proc->readAllStandardOutput()).trimmed();
                    }
                    startModeProc_ = nullptr;
                    proc->deleteLater();
                    if (slug != startMode_) {
                        startMode_ = slug;
                        emit startModeChanged();
                    }
                });
        connect(proc, &QProcess::errorOccurred, this, [this, proc](QProcess::ProcessError) {
            startModeProc_ = nullptr;
            proc->deleteLater();
            if (!startMode_.isEmpty()) {
                startMode_.clear();
                emit startModeChanged();
            }
        });
        proc->start(servicePath_, QStringList{QStringLiteral("query-start-mode")});
    }

signals:
    void statusChanged();
    void busyChanged();
    void startModeChanged();
    /// Emitted right before an elevated leg is dispatched to the worker.
    /// Fires once per leg, so a restart raises it twice ("stop" then
    /// "start") and an install raises it for "install" then "start".
    void operationStarted(QString operation);
    void operationCompleted(QString operation, bool success, QString errorMessage,
                            QString errorCode);
    void uacDeclined(QString operation);
    /// Emitted when a service-control action
    /// succeeds via the session elevation broker (non-elevated GUI). Reaching
    /// this means the broker is live (one UAC was granted this session), so
    /// the GUI marks the session as elevated — the review banner stops saying
    /// "will prompt once" and the "revoke administrator approval" control
    /// becomes available.
    void brokerSessionEstablished();

private slots:
    void onWorkerResult(QString operation, bool success, QString errorMessage) {
        emit operationCompleted(operation, success, errorMessage, QString());
        // Auto-start on successful install: registering the service with
        // SCM does not run it, but the user clicked "Install" expecting
        // a working service. Mirror the PowerShell scripts' install →
        // `sc start` step so the badge goes Running immediately.
        if (operation == QStringLiteral("install") && success) {
            refreshStatus();
            dispatch(QStringLiteral("start"), QStringLiteral("start"));
            return;
        }
        // Terminal leg — no chained operation follows. Clear busy before
        // refreshing the badge.
        setBusy(false, QString());
        // Refresh status after every operation so the badge + tray
        // update without waiting for the next polling tick.
        refreshStatus();
    }

    void onWorkerUacDeclined(QString operation) {
        // A declined UAC prompt ends the flow — the worker returned before
        // launching anything.
        setBusy(false, QString());
        emit uacDeclined(operation);
        refreshStatus();
    }

private:
    static constexpr const wchar_t *SERVICE_NAME = L"NetRuleRouter";
    // `product_identity::SYSTEMD_UNIT_NAME`; the host cannot link the Rust SSOT.
    static constexpr const char *SYSTEMD_UNIT = "netrulerouter.service";
    static constexpr int kSystemctlTimeoutMs = 2000;

    void applyStatus(Status next, const QString &reason) {
        if (next != status_ || reason != statusReason_) {
            status_ = next;
            statusReason_ = reason;
            emit statusChanged();
        }
        // Keep polling while a transition is in flight so transient
        // START_PENDING / STOP_PENDING states clear without a user click.
        if (status_ == StartPending || status_ == StopPending) {
            pendingPollTimer_.start(kPendingPollIntervalMs);
        } else {
            pendingPollTimer_.stop();
        }
    }

#ifndef Q_OS_WIN
    // Absolute, never PATH: whoever controls a PATH entry would answer for
    // systemd. `/bin` covers systems without the merged `/usr`.
    static QString systemctlPath() {
        for (const char *candidate : {"/usr/bin/systemctl", "/bin/systemctl"}) {
            const QString path = QString::fromLatin1(candidate);
            if (QFileInfo(path).isExecutable()) {
                return path;
            }
        }
        return QString();
    }

    // The same two properties the Rust systemd port reads, asked without
    // blocking: the GUI polls this, and a wait froze the window on every tick.
    // A query still running absorbs the next tick instead of stacking another.
    void querySystemdStatus() {
        if (statusProc_ != nullptr) {
            return;
        }
        const QString program = systemctlPath();
        if (program.isEmpty()) {
            applyStatus(Unknown, QStringLiteral("systemctl not found"));
            return;
        }
        auto *proc = new QProcess(this);
        statusProc_ = proc;
        connect(proc, &QProcess::finished, this,
                [this, proc](int, QProcess::ExitStatus exitStatus) {
                    statusProc_ = nullptr;
                    proc->deleteLater();
                    QString reason = QStringLiteral("systemctl show did not answer");
                    Status next = Unknown;
                    if (exitStatus == QProcess::NormalExit) {
                        next = parseSystemdStatus(
                            QString::fromUtf8(proc->readAllStandardOutput()), &reason);
                    }
                    applyStatus(next, reason);
                });
        // Every other error is followed by `finished`; a failed start is not.
        connect(proc, &QProcess::errorOccurred, this,
                [this, proc](QProcess::ProcessError error) {
                    if (error != QProcess::FailedToStart) {
                        return;
                    }
                    statusProc_ = nullptr;
                    proc->deleteLater();
                    applyStatus(Unknown, QStringLiteral("systemctl could not be started"));
                });
        QTimer::singleShot(kSystemctlTimeoutMs, proc, [proc]() { proc->kill(); });
        proc->start(program,
                    {QStringLiteral("show"), QStringLiteral("--property=LoadState,ActiveState"),
                     QStringLiteral("--"), QString::fromLatin1(SYSTEMD_UNIT)});
    }

    static Status parseSystemdStatus(const QString &output, QString *reason) {
        QString loadState;
        QString activeState;
        const QStringList lines = output.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
        for (const QString &line : lines) {
            if (line.startsWith(QLatin1String("LoadState=")))
                loadState = line.mid(10).trimmed();
            else if (line.startsWith(QLatin1String("ActiveState=")))
                activeState = line.mid(12).trimmed();
        }
        if (loadState == QLatin1String("not-found")) {
            *reason = QStringLiteral("Service not registered");
            return NotInstalled;
        }
        reason->clear();
        if (activeState == QLatin1String("active") || activeState == QLatin1String("reloading"))
            return Running;
        if (activeState == QLatin1String("activating"))
            return StartPending;
        if (activeState == QLatin1String("deactivating"))
            return StopPending;
        if (activeState == QLatin1String("inactive") || activeState == QLatin1String("failed"))
            return Stopped;
        *reason = QStringLiteral("systemctl reported LoadState=%1 ActiveState=%2")
                      .arg(loadState, activeState);
        return Unknown;
    }
#else
    Status queryStatus(QString *reason) const {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) {
            *reason = QStringLiteral("OpenSCManager failed: %1").arg(GetLastError());
            return Unknown;
        }
        SC_HANDLE svc = OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
        if (!svc) {
            const DWORD lastError = GetLastError();
            CloseServiceHandle(scm);
            if (lastError == ERROR_SERVICE_DOES_NOT_EXIST) {
                *reason = QStringLiteral("Service not registered");
                return NotInstalled;
            }
            *reason = QStringLiteral("OpenService failed: %1").arg(lastError);
            return Unknown;
        }
        SERVICE_STATUS_PROCESS statusProc{};
        DWORD bytes = 0;
        const BOOL ok = QueryServiceStatusEx(
            svc, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&statusProc), sizeof(statusProc), &bytes);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        if (!ok) {
            *reason = QStringLiteral("QueryServiceStatusEx failed: %1").arg(GetLastError());
            return Unknown;
        }
        reason->clear();
        switch (statusProc.dwCurrentState) {
            case SERVICE_RUNNING:        return Running;
            case SERVICE_STOPPED:        return Stopped;
            case SERVICE_START_PENDING:  return StartPending;
            case SERVICE_STOP_PENDING:   return StopPending;
            default:                     return Unknown;
        }
    }
#endif

    void dispatch(const QString &operation, const QString &command) {
#ifndef Q_OS_WIN
        // The launcher runs the action against the installed service and
        // locates it itself; no path from here is used.
        if (bridge_ != nullptr) {
            setBusy(true, operation);
            emit operationStarted(operation);
            dispatchViaBroker(operation, command);
            return;
        }
#endif
        if (servicePath_.isEmpty()) {
            setBusy(false, QString());
            emit operationCompleted(operation, false,
                QStringLiteral("Service binary not found"), QString());
            return;
        }
        setBusy(true, operation);
        emit operationStarted(operation);

        // A NON-elevated GUI routes the action
        // through the session elevation broker: the first UAC (an apply OR a
        // service action) spawns the broker, and every later privileged
        // action runs without another prompt. There is no throwaway
        // `runas` helper to hang (the restart-timeout / leftover-process
        // bug) — the broker runs `service.exe <command>` itself. An ALREADY
        // elevated GUI keeps the direct path (`runElevated` inherits the
        // token, no UAC).
        if (!nrrProcessIsElevated() && bridge_ != nullptr) {
            dispatchViaBroker(operation, command);
            return;
        }
        QMetaObject::invokeMethod(
            worker_, "runElevated", Qt::QueuedConnection,
            Q_ARG(QString, operation),
            Q_ARG(QString, servicePath_),
            Q_ARG(QString, command));
    }

    /// Send the service-control action to the launcher's broker over the
    /// RPC channel and resolve the operation when the single correlated
    /// response arrives. Mirrors `onWorkerResult` / `onWorkerUacDeclined`
    /// (including the install → start chain) so the broker path is
    /// behaviourally identical to the direct elevated path.
    ///
    /// An answer that never comes (launcher gone, broker killed) ends the
    /// operation as a timeout, or `busy` and the spinner would stay forever.
    void dispatchViaBroker(const QString &operation, const QString &command) {
        const QString corr = bridge_->emitServiceControlRpc(command, servicePath_);
        auto conn = std::make_shared<QMetaObject::Connection>();
        auto *deadline = new QTimer(this);
        deadline->setSingleShot(true);
        *conn = connect(
            bridge_, &NrrNativeBridge::rpcResponse, this,
            [this, conn, deadline, corr, operation](
                const QString &cid, bool ok, const QVariant &,
                const QString &errorCode, const QString &errorMessage) {
                if (cid != corr) { return; }
                QObject::disconnect(*conn);
                deadline->stop();
                deadline->deleteLater();
                onBrokerServiceControlResult(operation, ok, errorCode, errorMessage);
            });
        connect(deadline, &QTimer::timeout, this, [this, conn, deadline, operation]() {
            QObject::disconnect(*conn);
            deadline->deleteLater();
            onBrokerServiceControlResult(operation, false, QString(),
                                         nrrServiceOperationTimedOut());
        });
        deadline->start(kBrokerServiceControlTimeoutMs);
    }

    void onBrokerServiceControlResult(const QString &operation, bool ok,
                                      const QString &errorCode,
                                      const QString &errorMessage) {
        if (!ok && errorCode == QStringLiteral("uac-declined")) {
            setBusy(false, QString());
            emit uacDeclined(operation);
            refreshStatus();
            return;
        }
        if (!ok) {
            emit operationCompleted(operation, false, errorMessage, errorCode);
            setBusy(false, QString());
            refreshStatus();
            return;
        }
        emit operationCompleted(operation, true, QString(), QString());
#ifdef Q_OS_WIN
        // Reaching here means a service-control
        // action succeeded through the broker (non-elevated path), so the
        // broker session is live (UAC was granted). Tell the GUI so its
        // review banner + "revoke" control reflect the elevated session.
        emit brokerSessionEstablished();
#endif
#ifdef Q_OS_WIN
        // Auto-start after a successful install (mirrors onWorkerResult);
        // the broker is already up so this second action raises no UAC.
        // Elsewhere the install already starts the unit, and a start of its
        // own would ask for authorization a second time.
        if (operation == QStringLiteral("install")) {
            refreshStatus();
            dispatch(QStringLiteral("start"), QStringLiteral("start"));
            return;
        }
#endif
        setBusy(false, QString());
        refreshStatus();
    }

    // The service binary's file name on this OS (the product-identity names).
    static QString serviceBinaryName() {
#ifdef Q_OS_WIN
        return QStringLiteral("nrr-service.exe");
#else
        return QStringLiteral("nrr-serviced");
#endif
    }

    void setBusy(bool busy, const QString &operation) {
        const QString op = busy ? operation : QString();
        if (busy_ == busy && activeOperation_ == op) {
            return;
        }
        busy_ = busy;
        activeOperation_ = op;
        emit busyChanged();
    }

    QString servicePath_;
    /// Cache behind the `startMode` property, and the refresh in flight (null
    /// when none is).
    QString startMode_;
    QProcess *startModeProc_ = nullptr;
    /// The Linux `systemctl show` in flight (null when none is).
    QProcess *statusProc_ = nullptr;
    Status status_ = Unknown;
    QString statusReason_;
    bool busy_ = false;
    QString activeOperation_;
    QThread workerThread_;
    NrrServiceWorker *worker_ = nullptr;
    // Windows SCM has no status push, and the elevated
    // start/restart CLI returns while the service is still START_PENDING, so
    // the badge latched "Starting…/Stopping…" until the user clicked. This
    // single-shot timer re-polls while a *_PENDING transition is in flight
    // (armed/disarmed in refreshStatus), so every surface (GUI + tray) that
    // shares this controller converges on the settled state on its own.
    QTimer pendingPollTimer_;
    static constexpr int kPendingPollIntervalMs = 500;
    // RPC bridge for broker-routed service control (set in
    // main() via setBridge). Null until wired / for non-RPC launches.
    NrrNativeBridge *bridge_ = nullptr;
};
