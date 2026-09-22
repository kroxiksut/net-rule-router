#pragma once

#include "host_includes.h"

struct LaunchOptions {
    QString qmlPath;
    QString appIconPath;
    QString contextFilePath;
    // Where `nrr-service.exe` is, when it is not our sibling. Only a cargo
    // tree needs it: there the host is built into `target/<profile>/build/`
    // and the service sits next to the LAUNCHER instead.
    QString serviceExePath;
    // Where the surfaces coordinate: single-instance locks, activation
    // hand-off, shutdown flag. Passed by the launcher so the rule for choosing
    // it is declared once, in Rust — recomputing it here agreed with the
    // launcher on Windows only by coincidence, and would disagree on Linux,
    // where the launcher uses the per-user XDG runtime directory rather than
    // the shared `/tmp`.
    QString runtimeDirectory;
    int autoCloseMs = 0;
};

// Both spellings of the tray binary: the Cargo artifact name, identical on
// every OS, and the Unix one the product identity declares
// (`BinaryRole::Tray::unix_file_name`). They are two names for one program
// because Cargo cannot name a `[[bin]]` per OS, and the service tells its own
// surfaces apart by the peer's executable name — a tray running as
// `NetRuleRouterTray` on Linux is a program it cannot name, and every read it
// asks for comes back refused.
inline QStringList trayExecutableNames() {
#ifdef Q_OS_WIN
    return {QStringLiteral("NetRuleRouterTray.exe")};
#else
    return {QStringLiteral("netrulerouter-tray"), QStringLiteral("NetRuleRouterTray")};
#endif
}

inline QStringList mainGuiExecutableNames() {
#ifdef Q_OS_WIN
    return {QStringLiteral("NetRuleRouter.exe")};
#else
    return {QStringLiteral("netrulerouter"), QStringLiteral("NetRuleRouter")};
#endif
}

inline bool isTrayProductExecutable(const QString &applicationFilePath) {
    const QString baseName = QFileInfo(applicationFilePath).completeBaseName();
    for (const QString &name : trayExecutableNames()) {
        if (baseName.compare(QFileInfo(name).completeBaseName(), Qt::CaseInsensitive) == 0) {
            return true;
        }
    }
    return false;
}

inline LaunchOptions parseLaunchOptions(const QStringList &arguments) {
    LaunchOptions options;

    // The launcher always passes `--nrr-context-file=` to the host
    // (context emission happens in-process). Unknown args are ignored
    // silently.
    for (const QString &argument : arguments) {
        if (argument.startsWith("--qml=")) {
            options.qmlPath = argument.mid(QStringLiteral("--qml=").size()).trimmed();
        } else if (argument.startsWith("--nrr-app-icon=")) {
            options.appIconPath =
                argument.mid(QStringLiteral("--nrr-app-icon=").size()).trimmed();
        } else if (argument.startsWith("--nrr-context-file=")) {
            options.contextFilePath =
                argument.mid(QStringLiteral("--nrr-context-file=").size()).trimmed();
        } else if (argument.startsWith("--nrr-auto-close-ms=")) {
            options.autoCloseMs =
                argument.mid(QStringLiteral("--nrr-auto-close-ms=").size()).trimmed().toInt();
        } else if (argument.startsWith("--nrr-runtime-dir=")) {
            options.runtimeDirectory =
                argument.mid(QStringLiteral("--nrr-runtime-dir=").size()).trimmed();
        } else if (argument.startsWith("--nrr-service-exe=")) {
            options.serviceExePath =
                argument.mid(QStringLiteral("--nrr-service-exe=").size()).trimmed();
        }
    }

    return options;
}

inline QString normalizeLocalPath(const QString &rawValue) {
    if (rawValue.isEmpty()) {
        return {};
    }

    const QUrl asUrl(rawValue);
    if (asUrl.isValid() && asUrl.isLocalFile()) {
        return asUrl.toLocalFile();
    }

    return QDir::fromNativeSeparators(rawValue);
}

// A payload path the package ships with the binary: beside it, and in a dev
// build (`NRR_DEV_REPO_ROOT`, passed by build.rs for non-release profiles) in
// the checkout. Never a parent directory: on a shared machine any user can
// create folders at a drive root or in a shared temp folder above a binary.
inline QString findBundledFile(const QString &applicationDir, const QString &relativePath) {
    const QString beside = QDir(applicationDir).filePath(relativePath);
    if (QFileInfo::exists(beside)) {
        return QDir::cleanPath(beside);
    }
#ifdef NRR_DEV_REPO_ROOT
    const QString checkout = QDir(QStringLiteral(NRR_DEV_REPO_ROOT)).filePath(relativePath);
    if (QFileInfo::exists(checkout)) {
        return QDir::cleanPath(checkout);
    }
#endif
    return {};
}

// A product executable: our sibling, and in a dev build the cargo profile
// directory, since there the host is built deep under `target/<profile>/build`.
inline QString findProductExecutable(const QString &applicationDir, const QString &fileName) {
    const QString beside = QDir(applicationDir).filePath(fileName);
    if (QFileInfo::exists(beside)) {
        return QDir::cleanPath(beside);
    }
#ifdef NRR_DEV_BIN_DIR
    const QString dev = QDir(QStringLiteral(NRR_DEV_BIN_DIR)).filePath(fileName);
    if (QFileInfo::exists(dev)) {
        return QDir::cleanPath(dev);
    }
#endif
    return {};
}

// Startup splash for the main GUI. Loading the QML shell takes long enough
// (seconds in debug builds) that a user staring at nothing assumes the app
// hung or never started; a native splash paints immediately, before the QML
// engine begins loading, and is closed on the first real window show. The
// logo keeps its alpha channel: the splash is a frameless window with a
// translucent background, so only the logo pixels are visible — no opaque
// card behind them (QSplashScreen cannot do this: it flattens its pixmap
// opaquely against the desktop). Best-effort: a missing asset simply means
// no splash.
inline QWidget *createStartupSplash(const QString &applicationDir) {
    const QString logoPath = findBundledFile(
        applicationDir, QStringLiteral("assets/images/logo/logo-lockup-stacked.png"));
    if (logoPath.isEmpty()) {
        return nullptr;
    }
    QPixmap logo(logoPath);
    if (logo.isNull()) {
        return nullptr;
    }
    const QScreen *screen = QGuiApplication::primaryScreen();
    const qreal dpr = screen ? screen->devicePixelRatio() : 1.0;
    // Size against the actual screen, not a fixed constant: about a quarter
    // of the work area's width, capped so a large monitor does not get a
    // billboard, floored so a small one still shows a readable logo.
    const int screenLogicalWidth =
        screen ? screen->availableGeometry().width() : 1280;
    const int logicalLogoWidth = qBound(220, screenLogicalWidth / 4, 420);
    const int deviceLogoWidth = qRound(logicalLogoWidth * dpr);
    if (logo.width() > deviceLogoWidth) {
        logo = logo.scaledToWidth(deviceLogoWidth, Qt::SmoothTransformation);
    }
    logo.setDevicePixelRatio(dpr);
    auto *splash = new QWidget(nullptr, Qt::SplashScreen | Qt::FramelessWindowHint
                                            | Qt::WindowStaysOnTopHint);
    // Per-pixel alpha: the window surface itself is invisible; only the logo
    // pixels paint. WA_ShowWithoutActivating keeps keyboard focus wherever
    // the user had it — the splash is a status indicator, not a window to
    // interact with.
    splash->setAttribute(Qt::WA_TranslucentBackground);
    splash->setAttribute(Qt::WA_ShowWithoutActivating);
    auto *label = new QLabel(splash);
    label->setPixmap(logo);
    const QSize logicalSize = logo.deviceIndependentSize().toSize();
    label->resize(logicalSize);
    splash->resize(logicalSize);
    // A plain QWidget does not self-center the way QSplashScreen does.
    if (screen != nullptr) {
        const QRect area = screen->availableGeometry();
        splash->move(area.center()
                     - QPoint(logicalSize.width() / 2, logicalSize.height() / 2));
    }
    splash->show();
    return splash;
}

/// Absolute path of the Windows shell.
///
/// A bare `explorer.exe` is resolved against a PATH any process of this user
/// can prepend to; `%SystemRoot%` names the one Windows means.
inline QString systemExplorerPath() {
    const QString root = qEnvironmentVariable("SystemRoot");
    if (root.isEmpty()) {
        return QStringLiteral("explorer.exe");
    }
    return QDir(root).filePath(QStringLiteral("explorer.exe"));
}

inline QString resolveDefaultQmlRelativePath(const QString &applicationFilePath) {
    if (isTrayProductExecutable(applicationFilePath)) {
        return QStringLiteral("apps/desktop/qml/Tray.qml");
    }
    return QStringLiteral("apps/desktop/qml/Main.qml");
}

inline QString resolveQmlPath(const LaunchOptions &options,
                       const QString &applicationDir,
                       const QString &applicationFilePath) {
    const QString explicitPath = normalizeLocalPath(options.qmlPath);
    if (!explicitPath.isEmpty() && QFileInfo::exists(explicitPath)) {
        return explicitPath;
    }

    const QString envVariable = isTrayProductExecutable(applicationFilePath)
            ? QStringLiteral("NRR_QML_TRAY")
            : QStringLiteral("NRR_QML_MAIN");
    const QByteArray envVariableUtf8 = envVariable.toUtf8();
    const QString envPath =
        normalizeLocalPath(qEnvironmentVariable(envVariableUtf8.constData()));
    if (!envPath.isEmpty() && QFileInfo::exists(envPath)) {
        return envPath;
    }

    return findBundledFile(applicationDir, resolveDefaultQmlRelativePath(applicationFilePath));
}

// Windows takes the multi-size `.ico` the shell also embeds; X11 and the
// hicolor theme take a PNG. The launcher's `resolve_native_icon_path` chooses
// by the same rule — both sides must name the same file.
inline QString appIconRelativePath() {
#ifdef Q_OS_WIN
    return QStringLiteral("assets/icons/app/app.ico");
#else
    return QStringLiteral("assets/icons/app/icon-256.png");
#endif
}

inline QString resolveAppIconPath(const LaunchOptions &options, const QString &applicationDir) {
    const QString explicitPath = normalizeLocalPath(options.appIconPath);
    if (!explicitPath.isEmpty() && QFileInfo::exists(explicitPath)) {
        return explicitPath;
    }

    // TODO: elevated and non-elevated runs of the same binary occasionally
    // surface different taskbar icons; suspected AppUserModelID cache under HKCU.
    return findBundledFile(applicationDir, appIconRelativePath());
}

// Set once from `--nrr-runtime-dir=` before anything touches a lock or a flag.
// Empty only when the host was started without the argument (a hand-run of the
// binary), which keeps the historical Windows path working.
inline QString g_runtimeDirectoryOverride;

inline QString appRuntimeDirectoryPath() {
    const QString path =
        g_runtimeDirectoryOverride.isEmpty()
            ? QDir::cleanPath(QDir::tempPath() + QStringLiteral("/NetRuleRouter"))
            : g_runtimeDirectoryOverride;
    QDir().mkpath(path);
    return path;
}

inline QString productLockFilePath(bool trayProductExecutable) {
    return QDir(appRuntimeDirectoryPath())
        .filePath(trayProductExecutable ? QStringLiteral("tray-native.lock")
                                        : QStringLiteral("gui-native.lock"));
}

inline QString guiActivationRequestFilePath() {
    return QDir(appRuntimeDirectoryPath()).filePath(QStringLiteral("gui-activation.json"));
}

inline QString applicationShutdownFlagPath() {
    return QDir(appRuntimeDirectoryPath()).filePath(QStringLiteral("app-shutdown.flag"));
}

inline void writeApplicationShutdownFlag() {
    QFile flagFile(applicationShutdownFlagPath());
    if (flagFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        flagFile.close();
    }
}

inline void clearApplicationShutdownFlag() {
    QFile::remove(applicationShutdownFlagPath());
}

// Full reset uses a SEPARATE flag for the main-GUI -> tray "please exit"
// signal. Reusing `app-shutdown.flag` (which the tray's own Exit writes for
// the main GUI to consume) would race: the tray's poll could consume its own
// just-written flag before the main GUI sees it. A dedicated tray-only flag
// keeps the two shutdown directions independent.
inline QString trayShutdownFlagPath() {
    return QDir(appRuntimeDirectoryPath()).filePath(QStringLiteral("tray-shutdown.flag"));
}

inline void writeTrayShutdownFlag() {
    QFile flagFile(trayShutdownFlagPath());
    if (flagFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        flagFile.close();
    }
}

inline void clearTrayShutdownFlag() {
    QFile::remove(trayShutdownFlagPath());
}

// The launcher (Rust) writes `gui-activation.json` directly when it detects
// a primary instance is already running, in the same JSON shape the running
// `NrrNativeBridge::takePendingGuiRequest` consumes. The C++ host no longer
// needs its own writer for this file.

// The canonical name first: where both exist, the one the service can name is
// the one worth starting.
inline QString findProductExecutableNamed(const QString &applicationDir,
                                          const QStringList &names) {
    for (const QString &name : names) {
        const QString found = findProductExecutable(applicationDir, name);
        if (!found.isEmpty()) {
            return found;
        }
    }
    return {};
}

inline QString resolveMainGuiExecutable(const QString &applicationDir) {
    return findProductExecutableNamed(applicationDir, mainGuiExecutableNames());
}

inline QString resolveTrayGuiExecutable(const QString &applicationDir) {
    return findProductExecutableNamed(applicationDir, trayExecutableNames());
}

inline QString resolveLogsDirectory() {
    // QStandardPaths::AppLocalDataLocation on Windows returns
    // `<LOCALAPPDATA>/<organization>/<application>`. Both organization and
    // application are set to "NetRuleRouter", so the path comes out doubled
    // (`AppData\Local\NetRuleRouter\NetRuleRouter\...`). Bypass that and
    // build the canonical single-segment path manually so launcher (Rust) and
    // host (C++) both write to one place: `AppData\Local\NetRuleRouter\logs`.
    QStringList candidates;
#ifdef Q_OS_WIN
    const QString localAppData = qEnvironmentVariable("LOCALAPPDATA");
    if (!localAppData.isEmpty()) {
        candidates << QDir::cleanPath(
            localAppData + QStringLiteral("/NetRuleRouter/logs"));
    }
#endif
    const QString appLocalData =
        QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (!appLocalData.isEmpty()) {
        candidates << QDir::cleanPath(appLocalData + QStringLiteral("/logs"));
    }
    candidates << QDir::cleanPath(QDir::tempPath() + QStringLiteral("/NetRuleRouter/logs"));

    for (const QString &candidate : candidates) {
        if (QDir().mkpath(candidate)) {
            return candidate;
        }
    }
    return {};
}
