#include "native_bridge.h"

void NrrNativeBridge::deliverRpcResponse(const QString &line) {
    const QString body = stripPrefix(line, QStringLiteral("NRR_IPC_RESPONSE:"));
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(body.toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        qWarning().noquote() << "RPC response parse error:"
                             << parseError.errorString() << "line:" << line;
        return;
    }
    const QJsonObject obj = doc.object();
    const QString correlationId =
        obj.value(QStringLiteral("correlation-id")).toString();
    const bool ok = obj.value(QStringLiteral("ok")).toBool();
    QVariant payload;
    QString errorCode;
    QString errorMessage;
    if (ok) {
        payload = obj.value(QStringLiteral("payload")).toVariant();
    } else {
        const QJsonObject err = obj.value(QStringLiteral("error")).toObject();
        errorCode = err.value(QStringLiteral("code")).toString();
        errorMessage = err.value(QStringLiteral("message")).toString();
    }
    emit rpcResponse(correlationId, ok, payload, errorCode, errorMessage);
}

void NrrNativeBridge::deliverPushEvent(const QString &line) {
    const QString body = stripPrefix(line, QStringLiteral("NRR_IPC_PUSH:"));
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(body.toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        qWarning().noquote() << "RPC push parse error:"
                             << parseError.errorString() << "line:" << line;
        return;
    }
    const QJsonObject obj = doc.object();
    const QString subscriptionId =
        obj.value(QStringLiteral("subscription-id")).toString();
    const qint64 eventId =
        static_cast<qint64>(obj.value(QStringLiteral("event-id")).toDouble(0));
    const QVariant eventValue =
        obj.value(QStringLiteral("event")).toVariant();
    emit pushEvent(subscriptionId, eventId, eventValue);
}

QString NrrNativeBridge::emitRpcRequest(const QString &operation, const QJsonObject &payload) {
    const quint64 next = rpcCorrelationCounter_.fetch_add(1) + 1;
    const QString correlationId = QStringLiteral("c-%1").arg(next);
    QJsonObject envelope;
    envelope.insert(QStringLiteral("correlation-id"), correlationId);
    envelope.insert(QStringLiteral("operation"), operation);
    envelope.insert(QStringLiteral("payload"), payload);
    const QByteArray serialized =
        QJsonDocument(envelope).toJson(QJsonDocument::Compact);
    std::fputs("NRR_IPC_REQUEST:", stdout);
    std::fwrite(serialized.constData(), 1,
                static_cast<size_t>(serialized.size()), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
    return correlationId;
}

QString NrrNativeBridge::stripPrefix(const QString &s, const QString &prefix) {
    if (s.startsWith(prefix)) {
        return s.mid(prefix.size());
    }
    return s;
}

void NrrNativeBridge::setWindowDarkTitleBar(QObject *qmlWindow, bool dark) {
    applyDarkTitleBarToWindow(qobject_cast<QWindow *>(qmlWindow), dark);
}

void NrrNativeBridge::applyDarkTitleBarToWindow(QWindow *window, bool dark) {
#ifdef Q_OS_WIN
    if (window == nullptr) {
        return;
    }
    // winId() forces native HWND creation if it was deferred. Without this
    // the DwmSetWindowAttribute call on a not-yet-shown window is a no-op
    // and the first paint of the title bar uses the OS default colour.
    const HWND hwnd = reinterpret_cast<HWND>(window->winId());
    if (hwnd == nullptr) {
        return;
    }
    BOOL useDark = dark ? TRUE : FALSE;
    // Try the modern attribute first, fall back to the pre-20H1 one.
    // Either or both calls may return E_INVALIDARG on older builds —
    // ignore failures, the call is best-effort.
    DwmSetWindowAttribute(hwnd, 20, &useDark, sizeof(useDark));
    DwmSetWindowAttribute(hwnd, 19, &useDark, sizeof(useDark));
    // Already-shown windows need a non-client-area redraw to pick up the
    // attribute change at runtime — the OS only re-evaluates the dark
    // title bar on a paint cycle. SWP_FRAMECHANGED forces it.
    if (IsWindowVisible(hwnd)) {
        SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER
                         | SWP_NOACTIVATE | SWP_FRAMECHANGED);
        // Belt-and-suspenders for stubborn cases where DWM ignores the
        // first frame-changed redraw (some Win10 builds drop the first
        // immersive-dark-mode flip when the window had focus during the
        // attribute change). Forcing a non-client paint plus a redraw
        // of NCAREA reliably picks up the new attribute value.
        RedrawWindow(hwnd, nullptr, nullptr,
                     RDW_FRAME | RDW_INVALIDATE | RDW_UPDATENOW);
    }
#else
    Q_UNUSED(window);
    Q_UNUSED(dark);
#endif
}

void NrrNativeBridge::launchMainGui(const QString &section, bool about, bool license) {
    launchMainGuiWithAction(section, about, license, {}, {});
}

void NrrNativeBridge::launchMainGuiWithAction(const QString &section, bool about, bool license,
                                 const QString &action, const QString &reason) {
    if (mainGuiExecutable_.isEmpty()) {
        qWarning() << "NRR_LAUNCH_GUI mainGuiExecutable is empty (resolveMainGuiExecutable returned no path)";
        return;
    }

    // Pass the canonical launcher arguments directly — `nrr-launcher`
    // parses them via `parse_launch_request_arguments` (the same parser
    // the legacy Rust orchestrator used). No `--qml=` or
    // `--nrr-backend-*=` indirection: the launcher resolves QML in-process
    // and emits its own context.
    QStringList arguments;
    arguments << QStringLiteral("--source=tray");
    if (!section.isEmpty()) {
        arguments << QStringLiteral("--section=%1").arg(section);
    }
    if (about) {
        arguments << QStringLiteral("--about");
    }
    if (license) {
        arguments << QStringLiteral("--license");
    }
    if (!action.isEmpty()) {
        arguments << QStringLiteral("--action=%1").arg(action);
    }
    if (!reason.isEmpty()) {
        arguments << QStringLiteral("--reason=%1").arg(reason);
    }

    const QString workingDir = QFileInfo(mainGuiExecutable_).absolutePath();
    qWarning().noquote() << "NRR_LAUNCH_GUI exe=" << mainGuiExecutable_
                         << "args=" << arguments.join(" ")
                         << "cwd=" << workingDir;
    qint64 pid = -1;
    const bool success = QProcess::startDetached(mainGuiExecutable_, arguments, workingDir, &pid);
    qWarning().noquote() << "NRR_LAUNCH_GUI startDetached success=" << success
                         << "pid=" << pid;
}

void NrrNativeBridge::openLogsFolder() {
    if (logsDirectory_.isEmpty()) {
        qWarning() << "Logs directory was not resolved.";
        return;
    }
#ifdef Q_OS_WIN
    if (!QProcess::startDetached(systemExplorerPath(), {QDir::toNativeSeparators(logsDirectory_)})) {
        qWarning() << "Failed to open logs folder via explorer.exe.";
    }
#else
    QDesktopServices::openUrl(QUrl::fromLocalFile(logsDirectory_));
#endif
}

void NrrNativeBridge::watchTrayProcess(qint64 pid) {
    if (pid <= 0 || trayDeathReported_) {
        return;
    }
    // An already-confirmed, still-running tray keeps its PID: the new one
    // belongs to a duplicate launch that is about to exit on its own.
    if (trayProcessConfirmedAlive_ && trayProcessId_ > 0
        && probeProcessLiveness(trayProcessId_) == ProcessLiveness::Alive) {
        return;
    }
    trayProcessId_ = pid;
    trayProcessConfirmedAlive_ = false;
    trayShutdownExpected_ = false;
    trayLivenessPollCount_ = 0;
    trayLivenessGoneObservations_ = 0;
    trayLivenessLastOsError_ = 0;
    trayLivenessInconclusiveLogged_ = false;
    trayWatchElapsed_.start();
    if (!trayLivenessTimerConnected_) {
        trayLivenessTimer_.setInterval(kTrayLivenessPollIntervalMs);
        connect(&trayLivenessTimer_, &QTimer::timeout,
                this, &NrrNativeBridge::pollTrayLiveness);
        // An application-wide quit is a normal wind-down: whatever the
        // tray does after it must never be reported as an outside kill.
        connect(qApp, &QCoreApplication::aboutToQuit, this, [this]() {
            trayShutdownExpected_ = true;
            trayLivenessTimer_.stop();
        });
        trayLivenessTimerConnected_ = true;
    }
    trayLivenessTimer_.start();
}

void NrrNativeBridge::pollTrayLiveness() {
    if (trayProcessId_ <= 0 || trayDeathReported_) {
        trayLivenessTimer_.stop();
        return;
    }
    trayLivenessPollCount_ += 1;
    quint32 osError = 0;
    const ProcessLiveness liveness =
        probeProcessLiveness(trayProcessId_, &osError);
    if (liveness == ProcessLiveness::Alive) {
        if (!trayProcessConfirmedAlive_) {
            trayProcessConfirmedAlive_ = true;
            qWarning().noquote()
                << "NRR_HOST_TRAY_WATCH_ARMED pid=" << trayProcessId_
                << "observed_after_ms=" << trayWatchElapsed_.elapsed()
                << "polls=" << trayLivenessPollCount_;
        }
        return;
    }
    if (liveness == ProcessLiveness::Unknown) {
        // The OS refused to answer. Never a death verdict — the tray may
        // well be running; keep polling and say so once.
        trayLivenessLastOsError_ = osError;
        if (!trayLivenessInconclusiveLogged_) {
            trayLivenessInconclusiveLogged_ = true;
            qWarning().noquote()
                << "NRR_HOST_TRAY_WATCH_PROBE_INCONCLUSIVE pid="
                << trayProcessId_ << "os_error=" << osError
                << "confirmed_alive=" << trayProcessConfirmedAlive_;
        }
    } else {
        trayLivenessGoneObservations_ += 1;
    }

    if (!trayProcessConfirmedAlive_) {
        // Startup window: the tray launcher spawns its own Qt host child,
        // and on a loaded machine that whole chain takes seconds. Stay
        // silent until the window is over.
        if (trayWatchElapsed_.elapsed() < kTrayStartupObservationWindowMs) {
            return;
        }
        const qint64 idlePid = trayProcessId_;
        trayProcessId_ = 0;
        trayLivenessTimer_.stop();
        // Never seen alive within the window: duplicate-launch no-op (the
        // real tray belongs to another PID we do not know), an immediate
        // spawn failure, or a probe the OS never answered.
        const char *reason = trayLivenessGoneObservations_ > 0
                                 ? "never-observed-alive"
                                 : "probe-inconclusive";
        qWarning().noquote()
            << "NRR_HOST_TRAY_WATCH_IDLE reason=" << reason
            << "pid=" << idlePid
            << "waited_ms=" << trayWatchElapsed_.elapsed()
            << "polls=" << trayLivenessPollCount_
            << "gone_observations=" << trayLivenessGoneObservations_
            << "alive_observations=0"
            << "last_os_error=" << trayLivenessLastOsError_;
        return;
    }

    if (liveness != ProcessLiveness::Gone) {
        return;
    }
    const qint64 gonePid = trayProcessId_;
    trayProcessId_ = 0;
    trayLivenessTimer_.stop();
    // Intentional exits: the tray's own "Exit" (writes `app-shutdown.flag`
    // for the main GUI) and the main GUI's full reset (writes
    // `tray-shutdown.flag` for the tray). Both flags are CONSUMED on read
    // by their poller, so the file may already be gone by the time the
    // process actually exits — hence the latched `trayShutdownExpected_`
    // as well as the file check.
    if (trayShutdownExpected_ || QFile::exists(applicationShutdownFlagPath())
        || QFile::exists(trayShutdownFlagPath())) {
        qWarning().noquote()
            << "NRR_HOST_TRAY_EXITED_ON_REQUEST pid=" << gonePid
            << "expected_flag_latched=" << trayShutdownExpected_
            << "alive_for_ms=" << trayWatchElapsed_.elapsed();
        return;
    }
    trayDeathReported_ = true;
    qWarning().noquote() << "NRR_HOST_TRAY_DIED pid=" << gonePid
                         << "alive_for_ms=" << trayWatchElapsed_.elapsed()
                         << "polls=" << trayLivenessPollCount_;
    emit trayProcessDied();
}

NrrNativeBridge::ProcessLiveness NrrNativeBridge::probeProcessLiveness(qint64 pid,
                                                quint32 *osErrorOut) {
#ifdef Q_OS_WIN
    // SYNCHRONIZE is mandatory: `WaitForSingleObject` needs it on the
    // handle. Querying rights alone make every wait fail with
    // ERROR_ACCESS_DENIED, i.e. report every live process as gone.
    const HANDLE handle = OpenProcess(
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
        static_cast<DWORD>(pid));
    if (handle == nullptr) {
        const DWORD openError = GetLastError();
        if (osErrorOut != nullptr) {
            *osErrorOut = static_cast<quint32>(openError);
        }
        // ERROR_INVALID_PARAMETER is how Windows says "no such PID".
        // ERROR_ACCESS_DENIED means the PID exists but is not ours to
        // open (different integrity level) — that is proof of life.
        if (openError == ERROR_INVALID_PARAMETER) {
            return ProcessLiveness::Gone;
        }
        return openError == ERROR_ACCESS_DENIED ? ProcessLiveness::Alive
                                                : ProcessLiveness::Unknown;
    }
    // A live process never signals; an exited one signals immediately.
    // `WaitForSingleObject(..., 0)` therefore answers without blocking
    // and, unlike GetExitCodeProcess, cannot be fooled by a process that
    // legitimately returned STILL_ACTIVE (259) as its exit code.
    const DWORD waitResult = WaitForSingleObject(handle, 0);
    const DWORD waitError = GetLastError();
    CloseHandle(handle);
    if (waitResult == WAIT_TIMEOUT) {
        return ProcessLiveness::Alive;
    }
    if (waitResult == WAIT_OBJECT_0) {
        return ProcessLiveness::Gone;
    }
    if (osErrorOut != nullptr) {
        *osErrorOut = static_cast<quint32>(waitError);
    }
    return ProcessLiveness::Unknown;
#else
    // No watch on other platforms yet: never report the tray as gone.
    Q_UNUSED(pid);
    Q_UNUSED(osErrorOut);
    return ProcessLiveness::Alive;
#endif
}
