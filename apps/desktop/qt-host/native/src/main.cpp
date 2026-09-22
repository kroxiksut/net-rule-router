#include <QApplication>
#include <QClipboard>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDesktopServices>
#include <QDebug>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
#include <QIcon>
#include <QImage>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLockFile>
#include <QJsonValue>
#include <QLocale>
#include <QPainter>
#include <QPen>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QProcess>
#include <QScreen>
#include <QSplashScreen>
#include <QStandardPaths>
#include <QStringList>
#include <QStyleHints>
#include <QTimer>
#include <QThread>
#include <QUrl>
#include <QVariant>
#include <QWindow>

#include <atomic>
#include <cstdio>
#include <memory>
#include <iostream>
#include <string>

#ifdef Q_OS_WIN
#include <shobjidl_core.h>
#include <dwmapi.h>
#include <windows.h>
#include <io.h>
#endif

#include "host_support.h"
#include "native_bridge.h"
#include "rpc_stdin_reader.h"
#include "service_controller.h"

namespace {

QString pathToFileUrl(const QString &path) {
    return QUrl::fromLocalFile(QDir::fromNativeSeparators(path)).toString();
}

QVariantMap loadContextObject(const QString &contextFilePath, QString *errorMessage) {
    if (contextFilePath.isEmpty()) {
        return {};
    }

    QFile file(contextFilePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        if (errorMessage != nullptr) {
            *errorMessage = QStringLiteral("Failed to open context file '%1': %2")
                                .arg(contextFilePath, file.errorString());
        }
        return {};
    }

    QJsonParseError parseError;
    const QJsonDocument document =
        QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (errorMessage != nullptr) {
            *errorMessage = QStringLiteral("Failed to parse context JSON '%1': %2")
                                .arg(contextFilePath, parseError.errorString());
        }
        return {};
    }

    return document.object().toVariantMap();
}

void centerWindowOnScreen(QWindow *window) {
    if (window == nullptr) {
        return;
    }

    QScreen *screen = window->screen();
    if (screen == nullptr) {
        screen = QGuiApplication::primaryScreen();
    }
    if (screen == nullptr) {
        return;
    }

    const QRect available = screen->availableGeometry();
    const int x = available.x() + qMax(0, (available.width() - window->width()) / 2);
    const int y = available.y() + qMax(0, (available.height() - window->height()) / 2);
    window->setPosition(x, y);
}

void applyWindowIcon(QObject *object, const QIcon &icon) {
    if (object == nullptr || icon.isNull()) {
        return;
    }

    if (auto *window = qobject_cast<QWindow *>(object)) {
        window->setIcon(icon);
    }

    const QObjectList children = object->children();
    for (QObject *child : children) {
        applyWindowIcon(child, icon);
    }
}

#ifdef Q_OS_WIN
// Reinforce the taskbar icon via Win32 WM_SETICON on the native
// HWND, AFTER the window (and thus its taskbar button) exists. Qt's
// setWindowIcon already runs before show(), but with an explicit
// AppUserModelID and no registered shortcut the taskbar button can come up with
// a generic icon on the very FIRST launch (later launches cache the
// association). Re-asserting ICON_BIG/ICON_SMALL once the button exists nudges
// Windows to pick up the real app icon on that first launch. No-op when the icon
// file is absent.
void reinforceTaskbarIcon(QWindow *window, const QString &iconPath) {
    if (window == nullptr || iconPath.isEmpty()) {
        return;
    }
    const HWND hwnd = reinterpret_cast<HWND>(window->winId());
    if (hwnd == nullptr) {
        return;
    }
    const std::wstring wpath = iconPath.toStdWString();
    const int bigCx = GetSystemMetrics(SM_CXICON);
    const int bigCy = GetSystemMetrics(SM_CYICON);
    const int smallCx = GetSystemMetrics(SM_CXSMICON);
    const int smallCy = GetSystemMetrics(SM_CYSMICON);
    // The HICONs are intentionally NOT destroyed: they must outlive the window
    // (the taskbar/window keeps referencing them for the process lifetime).
    // NB: `small` is a Windows header macro (rpcndr.h `#define small char`), so
    // the locals must NOT be named `small`.
    if (HICON iconBig = static_cast<HICON>(
            LoadImageW(nullptr, wpath.c_str(), IMAGE_ICON, bigCx, bigCy, LR_LOADFROMFILE))) {
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(iconBig));
    }
    if (HICON iconSmall = static_cast<HICON>(
            LoadImageW(nullptr, wpath.c_str(), IMAGE_ICON, smallCx, smallCy, LR_LOADFROMFILE))) {
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(iconSmall));
    }
}
#endif

} // namespace

int main(int argc, char *argv[]) {
    // Disable stderr buffering so diagnostic markers reach the parent's
    // pipe even if the process is about to crash (no orphaned line buffer).
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    std::fputs("NRR_HOST_MAIN_ENTER\n", stderr);

    // Force Fusion style for Qt Quick Controls. The default native Windows
    // style routes Menu/MenuBar popups through Win32 native menus that
    // ignore custom QML delegates, so menu-shortcut text cannot be flushed
    // right by our two-column delegate. Fusion is a fully Qt-rendered style
    // — popups become QML Popups, the delegate is honoured, and `\t`-split
    // shortcut labels render right-aligned. We already override every other
    // user-facing control (Button/TextField/SpinBox/ComboBox) via the
    // `Themed*` wrappers, so Fusion only changes the look of remaining
    // bare controls (ScrollBar, TabBar, RadioButton, CheckBox, Slider) —
    // acceptable trade-off for correct menu rendering.
    QQuickStyle::setStyle(QStringLiteral("Fusion"));

    // Windows GUI-subsystem apps default Qt's message handler to
    // OutputDebugString (visible only in a debugger), so launcher's
    // stdout/stderr passthrough never sees qWarning/qDebug/qCritical.
    // Re-route them to stderr so they reach the launching shell.
    qInstallMessageHandler(
        [](QtMsgType, const QMessageLogContext &, const QString &message) {
            const QByteArray utf8 = message.toUtf8();
            std::fwrite(utf8.constData(), 1, static_cast<size_t>(utf8.size()), stderr);
            std::fputc('\n', stderr);
            std::fflush(stderr);
        });
    std::fputs("NRR_HOST_MSGHANDLER_INSTALLED\n", stderr);

    QApplication application(argc, argv);
    std::fputs("NRR_HOST_QAPP_CONSTRUCTED\n", stderr);
    const QString applicationFilePath = QCoreApplication::applicationFilePath();
    const bool trayProductExecutable = isTrayProductExecutable(applicationFilePath);
    QCoreApplication::setApplicationName(
        trayProductExecutable ? QStringLiteral("NetRuleRouterTray")
                              : QStringLiteral("NetRuleRouter"));
    QCoreApplication::setOrganizationName(QStringLiteral("NetRuleRouter"));

#ifdef Q_OS_WIN
    SetCurrentProcessExplicitAppUserModelID(
        trayProductExecutable ? L"NetRuleRouter.NetRuleRouterTray"
                              : L"NetRuleRouter.NetRuleRouter");
#endif

    const LaunchOptions options = parseLaunchOptions(QCoreApplication::arguments());
    const QString applicationDir = QCoreApplication::applicationDirPath();

    // Adopt the launcher's coordination directory BEFORE the first flag is
    // touched below — every lock and flag path is derived from it.
    if (!options.runtimeDirectory.isEmpty()) {
        g_runtimeDirectoryOverride =
            QDir::cleanPath(normalizeLocalPath(options.runtimeDirectory));
    }

    // A leftover shutdown flag from a previous tray "Exit" must not cause a
    // freshly launched process to terminate immediately. The flag is only
    // valid for a synchronous tray-to-GUI handover within a single session.
    clearApplicationShutdownFlag();
    // Same one-session validity for the Full-reset tray-shutdown flag.
    clearTrayShutdownFlag();

    // Single-instance enforcement is owned by the Rust launcher
    // (`SingleInstanceGuard` on `gui-shell-v1.lock` / `tray-shell-v1.lock`).
    // The launcher acquires its lock before spawning this host process, so a
    // duplicate host can only appear if the launcher itself was bypassed.
    // The host itself performs no lock check.

    const QString qmlPath = resolveQmlPath(options, applicationDir, applicationFilePath);
    if (qmlPath.isEmpty()) {
        qCritical("Main QML file was not resolved.");
        return 2;
    }
    const bool isMainGui = QFileInfo(qmlPath).fileName() == QStringLiteral("Main.qml");

#if defined(Q_OS_UNIX) && !defined(Q_OS_MACOS)
    // Wayland takes the window name and icon from the desktop entry matched by
    // app_id and ignores setWindowIcon, so each surface must name its own
    // entry. One host binary serves both, so the QML entry point is what tells
    // them apart here — the executable name cannot.
    QGuiApplication::setDesktopFileName(isMainGui
                                            ? QStringLiteral("netrulerouter")
                                            : QStringLiteral("netrulerouter-tray"));
#endif
    // Main GUI: window may be hidden by close-to-tray and re-shown via
    // activation handover from the tray; do not quit on last-window-hidden.
    // Tray: its own prompt windows open and close on demand (TrayPromptWindow),
    // and closing the last one must not take the tray down with it.
    // Real exit for both surfaces is driven by Qt.quit() from QML
    // (shutdown-flag polling for the main GUI; tray "Exit" handler for tray).
    application.setQuitOnLastWindowClosed(false);

    // The launcher always emits the context JSON in-process and passes it
    // via `--nrr-context-file=`. This host requires one — it is meant to be
    // launched by `nrr-launcher` only.
    const QString contextFilePath = normalizeLocalPath(options.contextFilePath);
    if (contextFilePath.isEmpty()) {
        qCritical("No context file passed via --nrr-context-file=. "
                  "This host is meant to be launched by `nrr-launcher`.");
        return 1;
    }

    QIcon appIcon;
    const QString iconPath = resolveAppIconPath(options, applicationDir);
    if (!iconPath.isEmpty()) {
        appIcon = QIcon(iconPath);
    }
    if (appIcon.isNull()) {
        appIcon = application.windowIcon();
    }
    if (!appIcon.isNull()) {
        application.setWindowIcon(appIcon);
    }

    QString contextError;
    QVariantMap contextObject;
    if (!contextFilePath.isEmpty()) {
        contextObject = loadContextObject(contextFilePath, &contextError);
        if (contextObject.isEmpty() && !contextError.isEmpty()) {
            qWarning().noquote() << contextError;
        }
    }

    // Theme is needed for the DWM dark title bar (at first window show), so
    // derive it once here. The startup splash is a translucent, alpha-only
    // logo widget and does not depend on the theme.
    const QVariantMap themeContext = contextObject.value("theme").toMap();
    const QString effectiveTheme = themeContext.value("effectiveMode").toString();
    const bool initialDark = (effectiveTheme == QStringLiteral("dark")
                              || effectiveTheme == QStringLiteral("high-contrast"));

    // Show the splash before any engine work: everything from here to the
    // first window show is the cold-start wait the splash exists to cover.
    QWidget *startupSplash = nullptr;
    if (isMainGui) {
        startupSplash = createStartupSplash(applicationDir);
        if (startupSplash != nullptr) {
            application.processEvents();
        }
    }

    // Context file cleanup belongs to the launcher (it owns the temp file
    // lifecycle); the C++ host no longer deletes it on exit.
    //
    // Both surfaces (Main.qml and Tray.qml) load through the same
    // QQmlApplicationEngine path. Tray.qml's root is a
    // `Qt.labs.platform.SystemTrayIcon` (native Win32 Shell_NotifyIcon API,
    // not QtWidgets), so right-click context menu rendering does not depend
    // on a top-level QWidget existing.
    NrrNativeBridge nativeBridge(applicationDir);

    // Start the stdin reader so `NRR_IPC_RESPONSE:` lines
    // from the launcher are routed to the bridge. The thread runs until
    // either the launcher drops the pipe (`getline` returns false) or the
    // event loop exits (the `aboutToQuit` lambda below closes stdin to
    // unblock the read, then we `wait()` before destruction so Qt6's
    // debug-build qFatal on "QThread destroyed while running" doesn't
    // fire on any exit path — including early QML-load failures that
    // would otherwise return from `main()` with the thread still in
    // its blocking read).
    RpcStdinReader rpcStdinReader(&nativeBridge);
    rpcStdinReader.start();
    QObject::connect(
        &application, &QCoreApplication::aboutToQuit, &application,
        [&rpcStdinReader]() { rpcStdinReader.requestStopAndCloseStdin(); });

    // Service Control Manager bridge. Q_INVOKABLE methods drive the Settings →
    // Service Management panel, the tray status badge, and the first-launch
    // install dialog.
    //
    // Declared BEFORE the engine, and therefore destroyed after it. It is a
    // context property of that engine, so the reverse order left the QML tree
    // being torn down with a context property that had already died — any
    // binding re-evaluated during teardown read a dangling pointer.
    NrrServiceController serviceController(applicationDir, options.serviceExePath);
    // Let a non-elevated GUI route service
    // control through the session elevation broker (one UAC per session).
    serviceController.setBridge(&nativeBridge);

    QQmlApplicationEngine engine;
    QObject::connect(
        &engine,
        &QQmlApplicationEngine::objectCreationFailed,
        &application,
        [](const QUrl &) { QCoreApplication::exit(1); },
        Qt::QueuedConnection);
    engine.rootContext()->setContextProperty(QStringLiteral("nrrNativeBridge"), &nativeBridge);
    engine.rootContext()->setContextProperty(
        QStringLiteral("nrrServiceController"), &serviceController);
    if (!contextFilePath.isEmpty()) {
        engine.rootContext()->setContextProperty(
            QStringLiteral("nrrContextFileUrl"), pathToFileUrl(contextFilePath));
        if (!contextObject.isEmpty()) {
            engine.rootContext()->setContextProperty(
                QStringLiteral("nrrLaunchContext"), contextObject);
        }
    }

    qWarning().noquote() << "NRR_HOST_LOADING_QML" << qmlPath << "isMainGui=" << isMainGui;
    engine.load(QUrl::fromLocalFile(qmlPath));
    qWarning().noquote() << "NRR_HOST_QML_LOADED rootObjects=" << engine.rootObjects().size();

    if (engine.rootObjects().isEmpty()) {
        qWarning() << "NRR_HOST_NO_ROOT_OBJECTS exiting";
        if (startupSplash != nullptr) {
            startupSplash->close();
            startupSplash->deleteLater();
            startupSplash = nullptr;
        }
        // Early-exit before `application.exec()`
        // means the aboutToQuit cleanup never fires. Drain the reader
        // here so the QThread destructor sees a stopped thread.
        rpcStdinReader.requestStopAndCloseStdin();
        rpcStdinReader.wait(2000);
        return 1;
    }

    if (!appIcon.isNull()) {
        const QObjectList rootObjects = engine.rootObjects();
        for (QObject *rootObject : rootObjects) {
            applyWindowIcon(rootObject, appIcon);
        }
    }

    if (isMainGui) {
        const QObjectList rootObjects = engine.rootObjects();
        int windowsShown = 0;

        for (QObject *rootObject : rootObjects) {
            if (auto *window = qobject_cast<QWindow *>(rootObject)) {
                if (windowsShown == 0) {
                    // Register the main window in the bridge BEFORE the
                    // first show so the DWM attribute is set on a created
                    // (but not yet visible) HWND — the very first paint then
                    // already uses the dark title bar. Component.onCompleted
                    // in QML ran during engine.load(), at which point the
                    // bridge had no window pointer yet, so its theme call
                    // was a no-op; this path is what makes the initial cold
                    // start render correctly.
                    nativeBridge.setMainWindow(window);
                    nativeBridge.setMainWindowDarkTitleBar(initialDark);
                }
                centerWindowOnScreen(window);
                window->show();
                window->requestActivate();
                // The real window is on screen — the splash's job is done.
                if (startupSplash != nullptr) {
                    startupSplash->close();
                    startupSplash->deleteLater();
                    startupSplash = nullptr;
                }
#ifdef Q_OS_WIN
                // Re-assert the taskbar icon once the main
                // window's button exists, to beat the first-launch generic-icon
                // quirk under the explicit AppUserModelID.
                if (windowsShown == 0) {
                    reinforceTaskbarIcon(window, iconPath);
                    // The pre-exec reinforce above races the shell: the
                    // taskbar button is created ASYNCHRONOUSLY after show() + the
                    // event loop starts pumping, so the icon can still come up
                    // generic on the very first launch (the suspected AppUserModelID
                    // cache miss — see TODO(taskbar-icon-non-admin)). Re-apply on the
                    // first event-loop turn AND after a short delay so at least one
                    // re-assert lands after the button exists. Idempotent/harmless
                    // (worst case it re-sets the icon already shown); `window` is the
                    // timer context so a closed window auto-cancels it.
                    QWindow *const iconWin = window;
                    const QString iconReapplyPath = iconPath;
                    QTimer::singleShot(0, window, [iconWin, iconReapplyPath]() {
                        reinforceTaskbarIcon(iconWin, iconReapplyPath);
                    });
                    QTimer::singleShot(600, window, [iconWin, iconReapplyPath]() {
                        reinforceTaskbarIcon(iconWin, iconReapplyPath);
                    });
                }
#endif
                ++windowsShown;
            } else {
                qWarning().noquote() << "NRR_HOST_ROOT_NOT_WINDOW class=" << rootObject->metaObject()->className();
            }
        }
        qWarning().noquote() << "NRR_HOST_WINDOWS_SHOWN" << windowsShown;
        // No window ever came up (all roots were non-window objects): the
        // splash must not outlive the loop and hang on screen.
        if (startupSplash != nullptr) {
            startupSplash->close();
            startupSplash->deleteLater();
            startupSplash = nullptr;
        }
    }

    if (options.autoCloseMs > 0) {
        QTimer::singleShot(options.autoCloseMs, &application, [&engine, isMainGui]() {
            if (isMainGui) {
                const QObjectList rootObjects = engine.rootObjects();
                for (QObject *rootObject : rootObjects) {
                    if (auto *window = qobject_cast<QWindow *>(rootObject)) {
                        window->close();
                    }
                }
            }
            QCoreApplication::quit();
        });
    }

    const int exitCode = application.exec();

    // Drain the stdin reader cleanly so the QThread
    // destructor doesn't fire on a still-running thread. The
    // aboutToQuit connection above already closed STDIN, so the
    // `getline` inside the reader has returned by now in nearly all
    // cases; the wait with a generous timeout covers the rare race
    // where the close hasn't propagated yet. If the timeout fires the
    // thread is still leaked but the process is exiting anyway —
    // better a deferred leak than a Win32 modal Debug Error dialog.
    if (rpcStdinReader.isRunning()) {
        // If aboutToQuit never fired (e.g. early-exit before exec()),
        // close stdin defensively here so wait() can return.
        rpcStdinReader.requestStopAndCloseStdin();
        rpcStdinReader.wait(2000);
    }
    return exitCode;
}
