#pragma once

#include "host_includes.h"

#ifndef Q_OS_WIN
#include <cerrno>
#include <sys/stat.h>
#include <unistd.h>
#endif

// Whether THIS process holds an elevated token (root on POSIX). An elevated
// process launches children without `runas`; the review flow warns when it is
// not. Fail-closed: a token that cannot be read counts as not elevated, so the
// warning shows and the broker handles the click.
inline bool nrrProcessIsElevated() {
#ifdef Q_OS_WIN
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) || token == nullptr) {
        return false;
    }
    TOKEN_ELEVATION elevation{};
    DWORD bytes = 0;
    const BOOL ok =
        GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &bytes);
    CloseHandle(token);
    return ok != FALSE && elevation.TokenIsElevated != 0;
#else
    return ::geteuid() == 0;
#endif
}

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

// The launcher passes every path argument plain; a `file://` URL is not a path.
inline QString normalizeLocalPath(const QString &rawValue) {
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

#ifdef Q_OS_WIN
// A DLL named without a path is looked for in System32 and beside this
// executable only: the default search also walks the current directory and
// PATH, which whoever starts the process chooses. The Rust twin is
// `nrr_platform_windows::dll_search`. Called first in `main`.
inline bool restrictDllSearch() {
    DWORD flags = LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR;
#ifdef NRR_DEV_QT_BIN_DIR
    flags |= LOAD_LIBRARY_SEARCH_USER_DIRS;
#endif
    if (!SetDefaultDllDirectories(flags)) {
        return false;
    }
    // A load asking for the classic order bypasses the list above; this drops
    // the current directory there.
    if (!SetDllDirectoryW(L"")) {
        return false;
    }
#ifdef NRR_DEV_QT_BIN_DIR
    const std::wstring kitBin =
        QDir::toNativeSeparators(QStringLiteral(NRR_DEV_QT_BIN_DIR)).toStdWString();
    return AddDllDirectory(kitBin.c_str()) != nullptr;
#else
    return true;
#endif
}
#endif

// A shipped Windows host takes Qt plugins and QML modules from the package
// only. Qt's defaults also follow environment variables, which reach even an
// elevated host from the user's own registry, and adopt the package's PARENT
// as the Qt prefix (`..\plugins`, `..\qml`) once `..\lib\Qt6Core.lib` exists.
// A dev host keeps the defaults: it runs against the Qt kit.
#if defined(Q_OS_WIN) && !defined(NRR_DEV_REPO_ROOT)
#define NRR_QT_PINNED_TO_PACKAGE

// Known before QApplication exists, unlike `applicationDirPath()`.
inline QString executableDirectory() {
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        const DWORD length =
            GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            return {};
        }
        if (length < buffer.size()) {
            buffer.resize(length);
            break;
        }
        if (buffer.size() >= 32768) {
            return {};
        }
        buffer.resize(buffer.size() * 2);
    }
    return QFileInfo(QString::fromStdWString(buffer)).absolutePath();
}

// The variables that name a directory or a library Qt loads code from. Those
// that only pick a plugin by name choose among what the pinned paths hold.
inline void pinQtPluginPaths(const QString &applicationDir) {
    for (const char *name : {"QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "QML_IMPORT_PATH",
                             "QML2_IMPORT_PATH", "QML_PLUGIN_PATH", "QT_OPENGL_DLL",
                             "QT_VULKAN_LIB"}) {
        qunsetenv(name);
    }
    if (!applicationDir.isEmpty()) {
        QCoreApplication::setLibraryPaths({applicationDir});
    }
}

// Keeps the modules compiled into our binaries and the package's own `qml`.
inline QStringList pinnedQmlImportPaths(const QStringList &current, const QString &applicationDir) {
    const QString package = QDir::cleanPath(applicationDir);
    const QString bundled = QDir::cleanPath(QDir(applicationDir).filePath(QStringLiteral("qml")));
    QStringList pinned;
    for (const QString &path : current) {
        const QString clean = QDir::cleanPath(path);
        const bool compiledIn =
            path.startsWith(QStringLiteral("qrc:")) || path.startsWith(QLatin1Char(':'));
        const bool inPackage = clean.compare(package, Qt::CaseInsensitive) == 0
                               || clean.compare(bundled, Qt::CaseInsensitive) == 0;
        if (compiledIn || inPackage) {
            pinned << path;
        }
    }
    if (!pinned.contains(bundled, Qt::CaseInsensitive)) {
        pinned << bundled;
    }
    return pinned;
}
#endif

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

inline QString resolveDefaultQmlRelativePath() {
    return QStringLiteral("apps/desktop/qml/Main.qml");
}

inline QString resolveQmlPath(const LaunchOptions &options,
                       const QString &applicationDir) {
    const QString explicitPath = normalizeLocalPath(options.qmlPath);
    if (!explicitPath.isEmpty() && QFileInfo::exists(explicitPath)) {
        return explicitPath;
    }

#ifdef NRR_DEV_REPO_ROOT
    // Dev builds only: in a shipped host the environment must not choose the QML it runs.
    const QString envPath = normalizeLocalPath(qEnvironmentVariable("NRR_QML_MAIN"));
    if (!envPath.isEmpty() && QFileInfo::exists(envPath)) {
        return envPath;
    }
#endif

    return findBundledFile(applicationDir, resolveDefaultQmlRelativePath());
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

// Set once by `adoptRuntimeDirectory` before anything touches a lock or a flag.
inline QString g_runtimeDirectoryOverride;

#ifndef Q_OS_WIN
// Owner-only, and never a symlink or another user's directory: the fallback
// sits in the shared temp dir, where anyone can plant our name first.
inline bool ensurePrivateDirectory(const QString &path) {
    const QByteArray native = QFile::encodeName(path);
    if (::mkdir(native.constData(), 0700) != 0 && errno != EEXIST) {
        return false;
    }
    struct stat info {};
    if (::lstat(native.constData(), &info) != 0) {
        return false;
    }
    return S_ISDIR(info.st_mode) && info.st_uid == ::geteuid() && (info.st_mode & 077) == 0;
}
#endif

// The launcher's directory, or for a hand-run of the binary a fallback in the
// temp dir (per-user already on Windows, per-uid and checked elsewhere).
// False when that fallback is not private to this user.
inline bool adoptRuntimeDirectory(const QString &launcherDirectory) {
    if (!launcherDirectory.isEmpty()) {
        g_runtimeDirectoryOverride = QDir::cleanPath(normalizeLocalPath(launcherDirectory));
        return true;
    }
#ifdef Q_OS_WIN
    return true;
#else
    const QString fallback = QDir::cleanPath(
        QDir::tempPath() + QStringLiteral("/NetRuleRouter-%1").arg(::geteuid()));
    if (!ensurePrivateDirectory(fallback)) {
        return false;
    }
    g_runtimeDirectoryOverride = fallback;
    return true;
#endif
}

inline QString appRuntimeDirectoryPath() {
    const QString path =
        g_runtimeDirectoryOverride.isEmpty()
            ? QDir::cleanPath(QDir::tempPath() + QStringLiteral("/NetRuleRouter"))
            : g_runtimeDirectoryOverride;
    QDir().mkpath(path);
    return path;
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

// The service log folder as a local path, from the launch context: the
// launcher resolves it (`ui_surface::logs_folder_url`) and puts it at
// `about.logsFolderUrl` (main window) or `logsFolderUrl` (tray). Empty when
// there is no such folder yet, so the host never opens one of its own.
inline QString logsDirectoryFromContext(const QVariantMap &context) {
    QString url = context.value(QStringLiteral("logsFolderUrl")).toString();
    if (url.isEmpty()) {
        url = context.value(QStringLiteral("about"))
                  .toMap()
                  .value(QStringLiteral("logsFolderUrl"))
                  .toString();
    }
    return url.isEmpty() ? QString() : QUrl(url).toLocalFile();
}
