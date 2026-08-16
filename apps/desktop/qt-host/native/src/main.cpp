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

namespace {

struct LaunchOptions {
    QString qmlPath;
    QString appIconPath;
    QString contextFilePath;
    // Where the surfaces coordinate: single-instance locks, activation
    // hand-off, shutdown flag. Passed by the launcher so the rule for choosing
    // it is declared once, in Rust — recomputing it here agreed with the
    // launcher on Windows only by coincidence, and would disagree on Linux,
    // where the launcher uses the per-user XDG runtime directory rather than
    // the shared `/tmp`.
    QString runtimeDirectory;
    int autoCloseMs = 0;
};

bool isTrayProductExecutable(const QString &applicationFilePath) {
    const QString baseName = QFileInfo(applicationFilePath).completeBaseName();
    return baseName.compare(QStringLiteral("NetRuleRouterTray"), Qt::CaseInsensitive) == 0;
}

LaunchOptions parseLaunchOptions(const QStringList &arguments) {
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
        }
    }

    return options;
}

QString normalizeLocalPath(const QString &rawValue) {
    if (rawValue.isEmpty()) {
        return {};
    }

    const QUrl asUrl(rawValue);
    if (asUrl.isValid() && asUrl.isLocalFile()) {
        return asUrl.toLocalFile();
    }

    return QDir::fromNativeSeparators(rawValue);
}

QString findUpwardFile(const QString &startDirectory,
                       const QString &relativePath,
                       int maxDepth = 10) {
    QDir current(startDirectory);
    for (int depth = 0; depth <= maxDepth; ++depth) {
        const QString candidate = current.filePath(relativePath);
        if (QFileInfo::exists(candidate)) {
            return QDir::cleanPath(candidate);
        }
        if (!current.cdUp()) {
            break;
        }
    }
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
QWidget *createStartupSplash(const QString &applicationDir) {
    const QString logoPath = findUpwardFile(
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

QString resolveDefaultQmlRelativePath(const QString &applicationFilePath) {
    if (isTrayProductExecutable(applicationFilePath)) {
        return QStringLiteral("apps/windows/qml/Tray.qml");
    }
    return QStringLiteral("apps/windows/qml/Main.qml");
}

QString resolveQmlPath(const LaunchOptions &options,
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

    const QString upward =
        findUpwardFile(applicationDir, resolveDefaultQmlRelativePath(applicationFilePath));
    if (!upward.isEmpty()) {
        return upward;
    }

    // Fall back to the absolute path baked at build time (CMake substitutes
    // these via target_compile_definitions). Required when the build target
    // directory is redirected to a separate disk and the binary cannot reach
    // the source tree by walking parent directories.
#if defined(NRR_QML_MAIN_DEFAULT) && defined(NRR_QML_TRAY_DEFAULT)
    const QString compiled = isTrayProductExecutable(applicationFilePath)
            ? QStringLiteral(NRR_QML_TRAY_DEFAULT)
            : QStringLiteral(NRR_QML_MAIN_DEFAULT);
    if (QFileInfo::exists(compiled)) {
        return compiled;
    }
#endif

    return {};
}

QString resolveAppIconPath(const LaunchOptions &options, const QString &applicationDir) {
    const QString explicitPath = normalizeLocalPath(options.appIconPath);
    if (!explicitPath.isEmpty() && QFileInfo::exists(explicitPath)) {
        return explicitPath;
    }

    // Fall back to an upward search relative to the host binary so
    // the icon still resolves even when the launcher's compile-time
    // path is not available (different build machine, redirected
    // target dir, etc.). Tried before giving up so a non-admin run
    // with a stale launcher doesn't end up with a generic taskbar
    // icon. TODO(taskbar-icon-non-admin): investigate why elevated
    // and non-elevated runs of the same binary occasionally surface
    // different taskbar icons; suspected AppUserModelID cache under
    // HKCU. Track with a separate sub-block.
    const QString upward =
        findUpwardFile(applicationDir, QStringLiteral("assets/icons/app/app.ico"));
    if (!upward.isEmpty()) {
        return upward;
    }
    // Last resort: try the workspace-relative paths the launcher
    // would have computed, in case the binary is running from a
    // sibling target dir without the workspace's assets being on
    // its upward search.
    for (const QString &candidate : {
             QStringLiteral("../../assets/icons/app/app.ico"),
             QStringLiteral("../../../assets/icons/app/app.ico"),
             QStringLiteral("../../../../assets/icons/app/app.ico"),
         }) {
        const QString abs = QDir(applicationDir).absoluteFilePath(candidate);
        if (QFileInfo::exists(abs)) {
            return abs;
        }
    }
    return QString();
}

// Set once from `--nrr-runtime-dir=` before anything touches a lock or a flag.
// Empty only when the host was started without the argument (a hand-run of the
// binary), which keeps the historical Windows path working.
QString g_runtimeDirectoryOverride;

QString appRuntimeDirectoryPath() {
    const QString path =
        g_runtimeDirectoryOverride.isEmpty()
            ? QDir::cleanPath(QDir::tempPath() + QStringLiteral("/NetRuleRouter"))
            : g_runtimeDirectoryOverride;
    QDir().mkpath(path);
    return path;
}

QString productLockFilePath(bool trayProductExecutable) {
    return QDir(appRuntimeDirectoryPath())
        .filePath(trayProductExecutable ? QStringLiteral("tray-native.lock")
                                        : QStringLiteral("gui-native.lock"));
}

QString guiActivationRequestFilePath() {
    return QDir(appRuntimeDirectoryPath()).filePath(QStringLiteral("gui-activation.json"));
}

QString applicationShutdownFlagPath() {
    return QDir(appRuntimeDirectoryPath()).filePath(QStringLiteral("app-shutdown.flag"));
}

void writeApplicationShutdownFlag() {
    QFile flagFile(applicationShutdownFlagPath());
    if (flagFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        flagFile.close();
    }
}

void clearApplicationShutdownFlag() {
    QFile::remove(applicationShutdownFlagPath());
}

// Full reset uses a SEPARATE flag for the main-GUI -> tray "please exit"
// signal. Reusing `app-shutdown.flag` (which the tray's own Exit writes for
// the main GUI to consume) would race: the tray's poll could consume its own
// just-written flag before the main GUI sees it. A dedicated tray-only flag
// keeps the two shutdown directions independent.
QString trayShutdownFlagPath() {
    return QDir(appRuntimeDirectoryPath()).filePath(QStringLiteral("tray-shutdown.flag"));
}

void writeTrayShutdownFlag() {
    QFile flagFile(trayShutdownFlagPath());
    if (flagFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        flagFile.close();
    }
}

void clearTrayShutdownFlag() {
    QFile::remove(trayShutdownFlagPath());
}

// The launcher (Rust) writes `gui-activation.json` directly when it detects
// a primary instance is already running, in the same JSON shape the running
// `NrrNativeBridge::takePendingGuiRequest` consumes. The C++ host no longer
// needs its own writer for this file.

QString resolveMainGuiExecutable(const QString &applicationDir) {
#ifdef Q_OS_WIN
    const QString executableName = QStringLiteral("NetRuleRouter.exe");
#else
    const QString executableName = QStringLiteral("NetRuleRouter");
#endif
    return findUpwardFile(applicationDir, executableName);
}

QString resolveTrayGuiExecutable(const QString &applicationDir) {
#ifdef Q_OS_WIN
    const QString executableName = QStringLiteral("NetRuleRouterTray.exe");
#else
    const QString executableName = QStringLiteral("NetRuleRouterTray");
#endif
    return findUpwardFile(applicationDir, executableName);
}

QString resolveLogsDirectory() {
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

class NrrNativeBridge : public QObject {
    Q_OBJECT

public:
    explicit NrrNativeBridge(const QString &applicationDir, QObject *parent = nullptr)
        : QObject(parent),
          applicationDir_(applicationDir),
          mainQmlPath_(findUpwardFile(applicationDir, QStringLiteral("apps/windows/qml/Main.qml"))),
          mainGuiExecutable_(resolveMainGuiExecutable(applicationDir)),
          trayGuiExecutable_(resolveTrayGuiExecutable(applicationDir)),
          guiActivationRequestPath_(guiActivationRequestFilePath()),
          logsDirectory_(resolveLogsDirectory()) {}

    Q_INVOKABLE void triggerTrayAction(const QString &actionId) {
        if (actionId == QStringLiteral("open-main-window")) {
            launchMainGui({}, false, false);
        } else if (actionId == QStringLiteral("interfaces-routes")) {
            launchMainGui(QStringLiteral("interfaces-routes"), false, false);
        } else if (actionId == QStringLiteral("rules")) {
            launchMainGui(QStringLiteral("rules"), false, false);
        } else if (actionId == QStringLiteral("diagnostics")) {
            launchMainGui(QStringLiteral("diagnostics"), false, false);
        } else if (actionId == QStringLiteral("logs")) {
            launchMainGui(QStringLiteral("logs"), false, false);
        } else if (actionId == QStringLiteral("settings")) {
            launchMainGui(QStringLiteral("settings"), false, false);
        } else if (actionId == QStringLiteral("refresh-interfaces")) {
            launchMainGui(QStringLiteral("interfaces-routes"), false, false);
        } else if (actionId == QStringLiteral("check-service-status")) {
            launchMainGui(QStringLiteral("diagnostics"), false, false);
        } else if (actionId == QStringLiteral("safe-rollback")) {
            launchMainGui(QStringLiteral("diagnostics"), false, false);
        } else if (actionId == QStringLiteral("temporary-disable-product-impact")) {
            launchMainGui(QStringLiteral("diagnostics"), false, false);
        } else if (actionId == QStringLiteral("rules-drift-apply")) {
            // "Apply" on the tray's "your rules files differ from what is
            // applied" notice. The tray never writes routing policy itself:
            // review, elevation and activation belong to the main window, so
            // the intent slug travels with the activation hand-off and the
            // window runs its normal load-from-file + review flow.
            launchMainGuiWithAction(QStringLiteral("rules"), false, false,
                                    QStringLiteral("rules-drift-apply"), {});
        } else if (actionId == QStringLiteral("open-about-window")) {
            launchMainGui({}, true, false);
        } else if (actionId == QStringLiteral("open-license-window")) {
            launchMainGui({}, false, true);
        } else if (actionId == QStringLiteral("open-logs-folder")) {
            openLogsFolder();
        } else if (actionId == QStringLiteral("exit-application")) {
            // Tray is the canonical "exit everything" entry point: write a
            // shutdown flag so the main GUI process (and, in the future, the
            // background service) can detect the request and terminate. Then
            // quit the tray's own event loop.
            writeApplicationShutdownFlag();
            QCoreApplication::quit();
        } else {
            qWarning().noquote() << "Unhandled tray action in native Qt bridge:" << actionId;
        }
    }

    Q_INVOKABLE bool savePreferences(const QString &serializedPayload) {
        // Persistence is the launcher's responsibility: it parses
        // `NRR_PREFS_JSON:<payload>` lines emitted via `console.log` from
        // QML on every preferences mutation, and writes the latest payload
        // back through `nrr-ui-support` after the host exits. The Qt host
        // therefore only needs to forward the marker on stdout — no
        // subprocess hop, no temp file.
        const QByteArray serialized = serializedPayload.toUtf8();
        std::fputs("NRR_PREFS_JSON:", stdout);
        std::fwrite(serialized.constData(), 1, static_cast<size_t>(serialized.size()), stdout);
        std::fputc('\n', stdout);
        std::fflush(stdout);
        return true;
    }

    Q_INVOKABLE QVariantMap takePendingGuiRequest() {
        QFile requestFile(guiActivationRequestPath_);
        if (!requestFile.exists()) {
            return {};
        }
        if (!requestFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            qWarning().noquote() << "Failed to open GUI activation request:"
                                 << guiActivationRequestPath_ << requestFile.errorString();
            return {};
        }

        QJsonParseError parseError;
        const QJsonDocument document =
            QJsonDocument::fromJson(requestFile.readAll(), &parseError);
        requestFile.close();
        QFile::remove(guiActivationRequestPath_);

        if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
            qWarning().noquote() << "Failed to parse GUI activation request:"
                                 << parseError.errorString();
            return {};
        }

        // The launcher logs that it wrote the request; without this line nothing
        // records that anyone read it, and a tray click that opens no window is
        // indistinguishable from one that was never delivered.
        std::printf("NRR_HOST_ACTIVATION_CONSUMED keys=%s\n",
                    document.object().keys().join(QLatin1Char(',')).toUtf8().constData());
        std::fflush(stdout);
        return document.object().toVariantMap();
    }

    /// SHA-256 hex digest of the UTF-8 bytes of an arbitrary QString.
    /// Used by the rules-update review flow to derive the
    /// `content-hash` field on dry-run payloads. The digest is
    /// computed locally with QCryptographicHash so we avoid an extra
    /// Rust round-trip per dry-run.
    ///
    /// Caveat: this hashes the QML-side string verbatim. JavaScript's
    /// `JSON.stringify` is not strictly canonical (insertion-order
    /// keys, no whitespace stripping); the result is deterministic
    /// *for our `_buildRulesJson` codepath* (which builds DTOs in a
    /// fixed order) but will NOT match a server-side hash computed
    /// from `nrr_shared::rules_json::to_canonical_string`. The wire
    /// schema treats `content-hash` as an opaque idempotency key —
    /// mismatch with the server just skips the dedup short-circuit,
    /// which is a soft failure (worst case: same rules trigger two
    /// reviews). Promotion to true canonical hashing is tracked as a
    /// follow-up.
    Q_INVOKABLE QString sha256Hex(const QString &input) {
        const QByteArray bytes = input.toUtf8();
        const QByteArray digest = QCryptographicHash::hash(
            bytes, QCryptographicHash::Sha256);
        return QString::fromLatin1(digest.toHex());
    }

    /// Decode a base64 payload as UTF-8 text. The legacy
    /// `decodeURIComponent(escape(Qt.atob(...)))` trick in QML throws
    /// `URIError: malformed URI sequence` on certain Cyrillic byte
    /// patterns (and Qt.atob itself is deprecated). Funneling base64
    /// decoding through Qt's `QByteArray::fromBase64` + `QString::fromUtf8`
    /// avoids the JS-side gymnastics and yields a clean QString.
    Q_INVOKABLE QString decodeBase64Utf8(const QString &b64) {
        const QByteArray raw = QByteArray::fromBase64(b64.toUtf8());
        return QString::fromUtf8(raw);
    }

    /// Convert a Unicode hostname (e.g. `пример.рф`) to its Punycode/ASCII
    /// representation (`xn--e1afmkfd.xn--p1ai`). Returns an empty string
    /// when the input is empty or already ASCII (no conversion needed —
    /// caller can detect equality to decide whether to hint Punycode in
    /// the UI). Qt's QUrl::toAce handles the IDNA2003 ToASCII algorithm
    /// per RFC 3490 / Unicode TR46 transitional rules.
    Q_INVOKABLE QString punycodeEncodeHost(const QString &hostname) {
        const QString trimmed = hostname.trimmed();
        if (trimmed.isEmpty()) return QString();
        bool allAscii = true;
        for (QChar ch : trimmed) {
            if (ch.unicode() > 127) { allAscii = false; break; }
        }
        if (allAscii) return QString();
        const QByteArray ace = QUrl::toAce(trimmed);
        return QString::fromLatin1(ace);
    }

    /// Convert a Punycode/ASCII hostname (e.g. `xn--p1ai`) to its
    /// Unicode representation (`рф`). Used by the GUI ↔ Service
    /// boundary: rules stored on the wire / WFP filters / SQLite are
    /// ACE-encoded, the GUI displays the human-readable form. Returns
    /// the input unchanged when no `xn--` label is present or the
    /// decoding fails. `QUrl::fromAce` round-trips through Unicode TR46.
    Q_INVOKABLE QString punycodeDecodeHost(const QString &hostname) {
        const QString trimmed = hostname.trimmed();
        if (trimmed.isEmpty()) return QString();
        if (!trimmed.contains(QStringLiteral("xn--"), Qt::CaseInsensitive)) {
            return trimmed;
        }
        const QString unicode = QUrl::fromAce(trimmed.toLatin1());
        if (unicode.isEmpty()) return trimmed;
        return unicode;
    }

    /// Place `text` on the system clipboard. Used by the Logs section
    /// "Copy row" context-menu so users can paste log lines into
    /// support tickets without selecting + Ctrl+C through several
    /// disjoint Label controls.
    Q_INVOKABLE void copyToClipboard(const QString &text) {
        QClipboard *cb = QGuiApplication::clipboard();
        if (cb != nullptr) {
            cb->setText(text);
        }
    }

    /// Work area of the screen the tray icon lives on — taskbar excluded,
    /// whichever edge it is docked to. QML sees only `Screen.desktopAvailable*`,
    /// which is the bounding box of EVERY screen: on a two-monitor desktop it
    /// put the tray notice past the right edge of the primary one and onto the
    /// neighbour, where an unseen window still silenced every notice behind it.
    /// Empty map means "no screen" — the caller keeps its own fallback.
    Q_INVOKABLE QVariantMap trayNoticeScreenGeometry() const {
        const QScreen *screen = QGuiApplication::primaryScreen();
        if (screen == nullptr) return QVariantMap();
        const QRect area = screen->availableGeometry();
        QVariantMap out;
        out.insert(QStringLiteral("x"), area.x());
        out.insert(QStringLiteral("y"), area.y());
        out.insert(QStringLiteral("width"), area.width());
        out.insert(QStringLiteral("height"), area.height());
        return out;
    }

    /// Return whether the current process is running with elevated
    /// privileges (Administrator). The service's
    /// `MutationSubmit` / `RoutePolicyUpdate` IPC ops gate on this via
    /// the named-pipe identity classifier, so the GUI uses the value
    /// to render an upfront warning in the review flow — better UX
    /// than letting the user reach ConfirmActivateDialog only to
    /// discover the activate phase fails with `forbidden`.
    /// Defaults to `true` on non-Windows or query failure so the
    /// warning never falsely fires.
    Q_INVOKABLE bool isElevated() {
#ifdef Q_OS_WIN
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)
                || token == nullptr) {
            return true;
        }
        TOKEN_ELEVATION elevation{};
        DWORD returned = 0;
        const BOOL ok = GetTokenInformation(token, TokenElevation,
                                            &elevation, sizeof(elevation),
                                            &returned);
        CloseHandle(token);
        if (ok == FALSE) {
            return true;
        }
        return elevation.TokenIsElevated != 0;
#else
        return true;
#endif
    }

    /// Open the OS file manager at the folder containing `path`, selecting
    /// the file when it exists. Used by the Rules section's "open source
    /// folder" affordance so the user can find the bound preset file.
    /// `path` is a local filesystem path (the launcher's `lastSavedPath*`).
    Q_INVOKABLE void openContainingFolder(const QString &path) {
        if (path.isEmpty()) {
            return;
        }
        const QString native = QDir::toNativeSeparators(path);
#ifdef Q_OS_WIN
        QFileInfo info(path);
        if (info.exists()) {
            // `/select,` highlights the file inside its folder.
            QProcess::startDetached(QStringLiteral("explorer.exe"),
                                    {QStringLiteral("/select,") + native});
        } else {
            // File gone — fall back to opening the parent directory.
            const QString dir = info.absolutePath();
            if (!dir.isEmpty()) {
                QProcess::startDetached(QStringLiteral("explorer.exe"),
                                        {QDir::toNativeSeparators(dir)});
            }
        }
#else
        QFileInfo info(path);
        QDesktopServices::openUrl(QUrl::fromLocalFile(
            info.exists() ? info.absolutePath() : path));
#endif
    }

    /// Programmatic grayscale of a tray icon. SystemTrayIcon on
    /// Qt.labs.platform only accepts a URL; runtime QImage transforms
    /// must be done off-band and saved to a file. We grayscale once on
    /// first call (preserving alpha so the tray still anti-aliases against
    /// the shell background) and cache the path. Returns the file:// URL
    /// of the cached PNG, or an empty string if the source could not be
    /// loaded.
    Q_INVOKABLE QString prepareTrayGrayscaleIcon(const QString &sourceUrl) {
        if (sourceUrl.isEmpty()) {
            return {};
        }
        if (!grayscaleIconCachePath_.isEmpty()
            && grayscaleIconCacheSource_ == sourceUrl
            && QFile::exists(grayscaleIconCachePath_)) {
            return QUrl::fromLocalFile(grayscaleIconCachePath_).toString();
        }

        QString localPath = sourceUrl;
        const QUrl asUrl(sourceUrl);
        if (asUrl.isLocalFile()) {
            localPath = asUrl.toLocalFile();
        }
        QImage source(localPath);
        if (source.isNull()) {
            qWarning().noquote() << "Failed to load tray icon source for grayscale:"
                                 << sourceUrl;
            return {};
        }
        QImage grayscale = source.convertToFormat(QImage::Format_ARGB32);
        for (int y = 0; y < grayscale.height(); ++y) {
            QRgb *row = reinterpret_cast<QRgb *>(grayscale.scanLine(y));
            for (int x = 0; x < grayscale.width(); ++x) {
                const QRgb pixel = row[x];
                const int gray = qGray(pixel);
                row[x] = qRgba(gray, gray, gray, qAlpha(pixel));
            }
        }
        const QString outDir = QStandardPaths::writableLocation(QStandardPaths::TempLocation)
                               + QStringLiteral("/NetRuleRouter");
        QDir().mkpath(outDir);
        const QString outPath = outDir + QStringLiteral("/tray-grayscale.png");
        if (!grayscale.save(outPath, "PNG")) {
            qWarning().noquote() << "Failed to save grayscale tray icon to" << outPath;
            return {};
        }
        grayscaleIconCacheSource_ = sourceUrl;
        grayscaleIconCachePath_ = outPath;
        return QUrl::fromLocalFile(outPath).toString();
    }

    /// Generic status-overlay icon compositor. Draws a colored dot in
    /// the bottom-right quadrant of the source icon and returns the
    /// file URL of the cached PNG.
    ///
    /// `statusKind` ∈ `{running, stopped, pending, not-installed,
    /// unknown, paused}`. Colors are hardcoded so QML can stay declarative.
    /// Single-entry cache keyed by `(sourceUrl, statusKind)`.
    Q_INVOKABLE QString prepareTrayStatusIcon(const QString &sourceUrl,
                                              const QString &statusKind) {
        if (sourceUrl.isEmpty()) {
            return {};
        }
        const QString cacheKey = sourceUrl + QStringLiteral(":") + statusKind;
        if (!statusIconCachePath_.isEmpty()
            && statusIconCacheKey_ == cacheKey
            && QFile::exists(statusIconCachePath_)) {
            return QUrl::fromLocalFile(statusIconCachePath_).toString();
        }

        QString localPath = sourceUrl;
        const QUrl asUrl(sourceUrl);
        if (asUrl.isLocalFile()) {
            localPath = asUrl.toLocalFile();
        }
        QImage source(localPath);
        if (source.isNull()) {
            qWarning().noquote() << "prepareTrayStatusIcon: failed to load"
                                 << sourceUrl;
            return {};
        }
        QImage composited = source.convertToFormat(QImage::Format_ARGB32);
        const int dotDiameter = qMax(composited.width(), composited.height()) / 3;
        QColor dotColor;
        if      (statusKind == QStringLiteral("running"))       dotColor = QColor("#2eb872");
        else if (statusKind == QStringLiteral("stopped"))       dotColor = QColor("#d4a017");
        else if (statusKind == QStringLiteral("pending"))       dotColor = QColor("#888888");
        else if (statusKind == QStringLiteral("not-installed")) dotColor = QColor("#c0392b");
        else if (statusKind == QStringLiteral("paused"))        dotColor = QColor("#f39c12");
        else                                                    dotColor = QColor("#888888");

        QPainter painter(&composited);
        painter.setRenderHint(QPainter::Antialiasing, true);
        painter.setBrush(dotColor);
        painter.setPen(Qt::NoPen);
        painter.drawEllipse(
            composited.width() - dotDiameter - 1,
            composited.height() - dotDiameter - 1,
            dotDiameter,
            dotDiameter);
        painter.end();

        const QString outDir = QStandardPaths::writableLocation(QStandardPaths::TempLocation)
                               + QStringLiteral("/NetRuleRouter");
        QDir().mkpath(outDir);
        const QString outPath = outDir + QStringLiteral("/tray-status-") + statusKind
                                + QStringLiteral(".png");
        if (!composited.save(outPath, "PNG")) {
            qWarning().noquote() << "prepareTrayStatusIcon: failed to save" << outPath;
            return {};
        }
        statusIconCacheKey_ = cacheKey;
        statusIconCachePath_ = outPath;
        return QUrl::fromLocalFile(outPath).toString();
    }

    Q_INVOKABLE bool ensureTrayRunning() {
        if (trayGuiExecutable_.isEmpty()) {
            qWarning().noquote()
                << "NRR_HOST_TRAY_SPAWN_FAIL reason=resolve-empty"
                << " applicationDir=" << applicationDir_;
            return false;
        }
        if (!QFileInfo::exists(trayGuiExecutable_)) {
            qWarning().noquote()
                << "NRR_HOST_TRAY_SPAWN_FAIL reason=not-found"
                << " path=" << trayGuiExecutable_;
            return false;
        }
        qint64 pid = 0;
        const QString workdir = QFileInfo(trayGuiExecutable_).absolutePath();
        const bool ok = QProcess::startDetached(
            trayGuiExecutable_, QStringList{}, workdir, &pid);
        if (!ok) {
            qWarning().noquote()
                << "NRR_HOST_TRAY_SPAWN_FAIL reason=startDetached-false"
                << " path=" << trayGuiExecutable_
                << " workdir=" << workdir;
        } else {
            qWarning().noquote()
                << "NRR_HOST_TRAY_SPAWN_OK pid=" << pid
                << " path=" << trayGuiExecutable_;
            watchTrayProcess(pid);
        }
        return ok;
    }

signals:
    /// Emitted at most once, when the tray process this host spawned is
    /// observed to have exited while no application-shutdown flag is present
    /// — i.e. it was killed from the outside (Task Manager, `taskkill`, a
    /// crash) rather than through the tray's own "Exit". QML reacts by
    /// running its normal application wind-down: without a tray icon there
    /// is no surface left to reopen or exit the application from, so an
    /// orphaned GUI (possibly hidden by close-to-tray) is unreachable.
    ///
    /// Deliberately NOT emitted when the shutdown flag exists: that is the
    /// intentional-exit path and its QML poller already drives the same
    /// wind-down.
    void trayProcessDied();

public:

    // The main GUI polls this from QML; when the tray's "Exit" handler has
    // written the shutdown flag, this returns true exactly once (the flag is
    // consumed) and the GUI then closes itself without minimising to tray.
    Q_INVOKABLE bool consumeApplicationShutdownRequest() {
        const QString path = applicationShutdownFlagPath();
        if (QFile::exists(path)) {
            QFile::remove(path);
            // Consuming the flag deletes it, so the tray-liveness watch would
            // no longer see it when the tray process finally goes away. Latch
            // the fact here instead of re-reading a file that is already gone.
            trayShutdownExpected_ = true;
            return true;
        }
        return false;
    }

    // Full reset: ask the tray to exit. The main GUI that initiates the
    // reset closes ITSELF directly (window.close + Qt.quit); this writes
    // the dedicated `tray-shutdown.flag` the tray polls
    // (`consumeTrayShutdownRequest`) so a "close everything" gesture takes
    // the tray down too. Separate from `app-shutdown.flag` to avoid a
    // consume race with the tray's own Exit path.
    Q_INVOKABLE bool requestTrayShutdown() {
        writeTrayShutdownFlag();
        // The tray consumes (deletes) the flag before it exits — latch the
        // intent so its exit is not read as an outside kill.
        trayShutdownExpected_ = true;
        return true;
    }

    // Tray polls this (Tray.qml) and quits when it returns true. Consumed
    // exactly once (the flag is deleted on read).
    Q_INVOKABLE bool consumeTrayShutdownRequest() {
        const QString path = trayShutdownFlagPath();
        if (QFile::exists(path)) {
            QFile::remove(path);
            return true;
        }
        return false;
    }

    // Full reset: delete the GUI/launcher log files (`*.log` in
    // %TEMP%\NetRuleRouter). Best-effort — a file the
    // launcher happens to hold open this instant is skipped (it reopens
    // append-mode per line, so it is usually closed). The service's own
    // operational logs are cleared via the `logs.clear` RPC, and the
    // security audit trail is deliberately never touched.
    Q_INVOKABLE int clearGuiLogs() {
        QDir dir(appRuntimeDirectoryPath());
        const QStringList logs =
            dir.entryList(QStringList() << QStringLiteral("*.log"), QDir::Files);
        int removed = 0;
        for (const QString &name : logs) {
            if (QFile::remove(dir.filePath(name))) {
                removed += 1;
            }
        }
        return removed;
    }

    void setMainWindow(QWindow *window) { mainWindow_ = window; }

    // Apply Windows DWM dark title bar to the main window. Native title bar
    // is rendered by the OS and ignores Qt palette / QML theme tokens, so a
    // dark/high-contrast app theme leaves the title bar light. Toggling
    // `DWMWA_USE_IMMERSIVE_DARK_MODE` (attribute 20 on Win10 20H1+/Win11,
    // attribute 19 on Win10 1809–1909) flips the OS-rendered title bar to
    // its dark variant. Called from QML on every theme change.
    Q_INVOKABLE void setMainWindowDarkTitleBar(bool dark) {
        applyDarkTitleBarToWindow(mainWindow_, dark);
    }

    // ── RPC bridge to launcher ────────────────────────────────────────────
    //
    // QML invokes one of the `rpc<Op>` Q_INVOKABLE methods with a
    // payload (catalog: `nrr_shared::ipc::IpcOperationName`). The
    // bridge:
    //   1. mints a unique `correlation_id` (process-local monotonic);
    //   2. emits `NRR_IPC_REQUEST:<json>` on stdout (the launcher's
    //      stdout reader picks it up and dispatches via NamedPipeIpcClient);
    //   3. returns the correlation_id immediately so QML can connect a
    //      one-shot handler;
    //   4. when the launcher writes back `NRR_IPC_RESPONSE:<json>` on
    //      this process's stdin, the `RpcStdinReader` thread parses it
    //      and emits the `rpcResponse(...)` signal, which QML routes by
    //      correlation_id.
    //
    // The signal is emitted with a `Qt::QueuedConnection` semantics by
    // virtue of crossing thread boundaries — Qt's signal/slot delivery
    // automatically marshals to the receiver's thread.

signals:
    /// Emitted on the GUI thread whenever a `NRR_IPC_RESPONSE:` line
    /// arrives from the launcher. QML connects once and demultiplexes
    /// by `correlationId`. `ok = true` ⇒ `payload` carries the JSON
    /// response object. `ok = false` ⇒ `errorCode` + `errorMessage`
    /// are populated, `payload` is empty.
    void rpcResponse(QString correlationId, bool ok, QVariant payload,
                     QString errorCode, QString errorMessage);

public:
    /// QML uses this to populate the health snapshot on cold start and
    /// after reconnects.
    Q_INVOKABLE QString rpcServiceHealthGet() {
        return emitRpcRequest(QStringLiteral("service.health.get"), QJsonObject());
    }

    /// Write the caller's per-SID route policy (default route / behavior
    /// mode for traffic not matched by a rule). `payload` is a full
    /// RoutePolicyUpdateRequest (primary?/secondary?/mode/
    /// block-secondary-when-unavailable/binding-source). This is a PRIVILEGED
    /// mutation: a non-elevated GUI's request returns Forbidden, which the
    /// launcher transparently relays through the session elevation broker (one
    /// UAC, reused for the session) — same path as MutationSubmit.
    Q_INVOKABLE QString rpcRoutePolicyUpdate(const QVariantMap &payload) {
        return emitRpcRequest(QStringLiteral("route.policy.update"),
                              QJsonObject::fromVariantMap(payload));
    }

    /// Persist the caller's confirmed VPN/link-provider executables as
    /// the service-side SSOT. `payload`
    /// is a RouteLinkProviderSetRequest ({role, link-provider-apps:[{exe-path,
    /// display-name}, ...]}); an empty app list clears the set. Feeds the
    /// per-app kill-switch exemptions and triggers an immediate server-side
    /// recompile. Same privileged relay path as `rpcRoutePolicyUpdate`.
    Q_INVOKABLE QString rpcRouteLinkProviderSet(const QVariantMap &payload) {
        return emitRpcRequest(QStringLiteral("route.link-provider.set"),
                              QJsonObject::fromVariantMap(payload));
    }

    /// The hosts a routed site turned out to need, parked by the service
    /// while `auto-rules-mode` is `suggest`.
    /// The tray lists the pending candidates and then accepts or dismisses a
    /// set of them; both mutations take `{"ids": ["..."]}`. Payloads are opaque
    /// pass-through — the wire shapes live in `nrr_shared::ipc_payloads`.
    Q_INVOKABLE QString rpcAutoRuleCandidatesList() {
        return emitRpcRequest(QStringLiteral("autorules.candidates.list"),
                              QJsonObject());
    }
    Q_INVOKABLE QString rpcAutoRuleCandidatesAccept(const QVariantMap &payload) {
        return emitRpcRequest(QStringLiteral("autorules.candidates.accept"),
                              QJsonObject::fromVariantMap(payload));
    }
    Q_INVOKABLE QString rpcAutoRuleCandidatesDismiss(const QVariantMap &payload) {
        return emitRpcRequest(QStringLiteral("autorules.candidates.dismiss"),
                              QJsonObject::fromVariantMap(payload));
    }
    /// Erases the service's memory of these suggestions (`{"ids": ["..."]}`) —
    /// the pending offer, the refusal and the quiet period after authoring —
    /// so the host is offered again once the evidence returns. Unlike a
    /// refusal, this records no answer.
    Q_INVOKABLE QString rpcAutoRuleCandidatesForget(const QVariantMap &payload) {
        return emitRpcRequest(QStringLiteral("autorules.candidates.forget"),
                              QJsonObject::fromVariantMap(payload));
    }

    /// Refusals the user recorded via `rpcAutoRuleCandidatesDismiss`, for a
    /// "review your declined suggestions" surface. `rpcAutoRuleDismissedRestore`
    /// undoes a set of them (`{"ids": ["..."]}`) so the underlying hosts may be
    /// offered again — it does not resurrect the original offer, which
    /// re-appears the next time the site pulls the host.
    Q_INVOKABLE QString rpcAutoRuleDismissedList() {
        return emitRpcRequest(QStringLiteral("autorules.dismissed.list"),
                              QJsonObject());
    }
    Q_INVOKABLE QString rpcAutoRuleDismissedRestore(const QVariantMap &payload) {
        return emitRpcRequest(QStringLiteral("autorules.dismissed.restore"),
                              QJsonObject::fromVariantMap(payload));
    }

    /// Block-notice mutes: silence future notices for one host, one app, or
    /// everything. `rpcBlockNoticeMutesSet`/`Remove` take `{"scope": {...}}`
    /// (kind: host/app/all); `Set` also takes an optional `until-unix-ms`
    /// (absent = indefinite). Every response carries the caller's full mute
    /// list. Wire shapes live in `nrr_shared::ipc_payloads::BlockNoticeMutes*`.
    Q_INVOKABLE QString rpcBlockNoticeMutesList() {
        return emitRpcRequest(QStringLiteral("block-notices.mutes.list"),
                              QJsonObject());
    }
    Q_INVOKABLE QString rpcBlockNoticeMutesSet(const QVariantMap &payload) {
        return emitRpcRequest(QStringLiteral("block-notices.mutes.set"),
                              QJsonObject::fromVariantMap(payload));
    }
    Q_INVOKABLE QString rpcBlockNoticeMutesRemove(const QVariantMap &payload) {
        return emitRpcRequest(QStringLiteral("block-notices.mutes.remove"),
                              QJsonObject::fromVariantMap(payload));
    }
    Q_INVOKABLE QString rpcBlockNoticeMutesClear() {
        return emitRpcRequest(QStringLiteral("block-notices.mutes.clear"),
                              QJsonObject());
    }

    /// Turn one blocked destination into a rule that routes it over the
    /// additional link. `payload` is `{"destination": "<hostname>"}`.
    Q_INVOKABLE QString rpcBlockNoticeRouteToSecondary(const QVariantMap &payload) {
        return emitRpcRequest(QStringLiteral("block-notices.route-to-secondary"),
                              QJsonObject::fromVariantMap(payload));
    }

    /// Full-reset support: erase the caller's auxiliary per-principal rows.
    /// No payload; response carries `{rows-deleted, tables-touched}`.
    Q_INVOKABLE QString rpcPrincipalDataPurge() {
        return emitRpcRequest(QStringLiteral("principal-data.purge"),
                              QJsonObject());
    }

    /// Read the SHARED DoH/DoT resolver baseline list (machine-wide,
    /// seeded with public resolvers by country). Read op, no
    /// elevation. The callback lands on `rpcResponse` with
    /// `{resolvers:[{target-kind, target, comment, enabled}, ...]}`.
    Q_INVOKABLE QString rpcDohResolversGet() {
        return emitRpcRequest(QStringLiteral("doh.resolvers.get"), QJsonObject());
    }

    // Read today+session totals (+ optional CSV) and write the
    // service-global traffic-stats settings.
    Q_INVOKABLE QString rpcTrafficStatsGet(const QVariantMap &payload) {
        return emitRpcRequest(QStringLiteral("traffic-stats.get"),
                              QJsonObject::fromVariantMap(payload));
    }
    Q_INVOKABLE QString rpcTrafficStatsSet(const QVariantMap &payload) {
        return emitRpcRequest(QStringLiteral("traffic-stats.set"),
                              QJsonObject::fromVariantMap(payload));
    }
    Q_INVOKABLE QString rpcTrafficStatsClear() {
        return emitRpcRequest(QStringLiteral("traffic-stats.clear"), QJsonObject());
    }

    /// Replace the ENTIRE shared DoH/DoT resolver baseline list.
    /// `resolversJson` is a serialised
    /// `{"resolvers":[{"target-kind":..,"target":..,"comment":..,"enabled":..}]}`
    /// object (JSON string so the array-of-objects payload rides one argument).
    /// PRIVILEGED — it edits the machine-wide baseline; a non-elevated GUI's
    /// request returns Forbidden, which the launcher transparently relays
    /// through the session elevation broker (one UAC, reused), same path as
    /// `rpcRoutePolicyUpdate`. A successful replace recompiles the caller's
    /// DoH-lockdown blocks at once.
    Q_INVOKABLE QString rpcDohResolversSet(const QString &resolversJson) {
        QJsonParseError parseError{};
        const QJsonDocument doc =
            QJsonDocument::fromJson(resolversJson.toUtf8(), &parseError);
        QJsonObject obj;
        if (parseError.error == QJsonParseError::NoError && doc.isObject()) {
            obj = doc.object();
        }
        return emitRpcRequest(QStringLiteral("doh.resolvers.set"), obj);
    }

    /// Revoke the session elevation broker (the GUI's "revoke administrator
    /// approval" action). Routed to the launcher's
    /// `local.broker-revoke`, which retires the live elevated broker so the
    /// next privileged op prompts UAC again. No-op when no session is live.
    Q_INVOKABLE QString rpcBrokerRevoke() {
        return emitRpcRequest(QStringLiteral("local.broker-revoke"), QJsonObject());
    }

    /// Probe of the elevation broker: is an elevated session live? Answered
    /// locally by the launcher (never spawns the broker, never prompts).
    /// Polled from the GUI status tick so the "revoke administrator approval"
    /// affordance reflects elevation acquired through ANY path, not just
    /// service-control actions. The payload may carry
    /// `auto-revoke-idle-secs` (0 = disabled) — the launcher retires a
    /// session that has sat unused at least that long and reports it via
    /// `auto-revoked` in the response.
    Q_INVOKABLE QString rpcBrokerStatus(const QJsonObject &payload) {
        return emitRpcRequest(QStringLiteral("local.broker-status"), payload);
    }

    /// Relay a privileged service-control action
    /// (start/stop/restart/install/uninstall) through the launcher's
    /// session elevation broker. Called from `NrrServiceController` for a
    /// NON-elevated GUI so the first UAC (an apply OR a service action)
    /// spawns the broker and every later privileged action runs without
    /// another prompt. The launcher routes `local.service-control` to the
    /// broker, which executes `<service-exe-path> <action>` already-elevated.
    QString emitServiceControlRpc(const QString &action,
                                  const QString &serviceExePath) {
        QJsonObject obj;
        obj.insert(QStringLiteral("action"), action);
        obj.insert(QStringLiteral("service-exe-path"), serviceExePath);
        return emitRpcRequest(QStringLiteral("local.service-control"), obj);
    }

    /// The big one — bundled initial state for the GUI's first render.
    Q_INVOKABLE QString rpcSnapshotInitialGet() {
        return emitRpcRequest(QStringLiteral("snapshot.initial.get"), QJsonObject());
    }

    /// Fetch the active revision's rules table (`rules.list`, a read
    /// op — no elevation needed). Empty
    /// payload means "all routes" (server-side default). The GUI uses
    /// this to rebind the table to what the service actually enforces
    /// after an activation, on a `revision-status-changed` push, or on
    /// the "Show rules applied by the service" toolbar action.
    Q_INVOKABLE QString rpcRulesList() {
        return emitRpcRequest(QStringLiteral("rules.list"), QJsonObject());
    }

    Q_INVOKABLE QString rpcRetentionSettingsGet() {
        return emitRpcRequest(QStringLiteral("settings.retention.get"), QJsonObject());
    }
    Q_INVOKABLE QString rpcRetentionSettingsSet(const QVariantMap &payload) {
        return emitRpcRequest(QStringLiteral("settings.retention.set"),
                              QJsonObject::fromVariantMap(payload));
    }

    // Operational-log + audit NDJSON retention config get/set.
    Q_INVOKABLE QString rpcLogRetentionConfigGet() {
        return emitRpcRequest(QStringLiteral("settings.log-retention.get"), QJsonObject());
    }
    Q_INVOKABLE QString rpcLogRetentionConfigSet(const QVariantMap &payload) {
        return emitRpcRequest(QStringLiteral("settings.log-retention.set"),
                              QJsonObject::fromVariantMap(payload));
    }

    Q_INVOKABLE QString rpcApplyFailurePolicyGet() {
        return emitRpcRequest(QStringLiteral("settings.apply-failure-policy.get"),
                              QJsonObject());
    }
    Q_INVOKABLE QString rpcApplyFailurePolicySet(const QString &policy) {
        QJsonObject obj;
        obj.insert(QStringLiteral("policy"), policy);
        return emitRpcRequest(QStringLiteral("settings.apply-failure-policy.set"), obj);
    }

    /// On-demand storage usage walk.
    Q_INVOKABLE QString rpcStorageUsageGet() {
        return emitRpcRequest(QStringLiteral("storage.usage.get"), QJsonObject());
    }

    /// Third-party components shipped with the product: publisher, licence,
    /// and a live integrity check (path, SHA-256, signer) of the binaries.
    /// Answered by the service, which owns the platform ports.
    Q_INVOKABLE QString rpcThirdPartyComponentsList() {
        return emitRpcRequest(QStringLiteral("third-party.components.list"), QJsonObject());
    }

    Q_INVOKABLE QString rpcRoutingPauseGet() {
        return emitRpcRequest(QStringLiteral("routing.pause.get"), QJsonObject());
    }
    Q_INVOKABLE QString rpcRoutingPauseToggle(bool paused, const QString &reason) {
        QJsonObject obj;
        obj.insert(QStringLiteral("paused"), paused);
        if (!reason.isEmpty()) {
            obj.insert(QStringLiteral("reason"), reason);
        }
        return emitRpcRequest(QStringLiteral("routing.pause.toggle"), obj);
    }

    Q_INVOKABLE QString rpcAutostartGet() {
        return emitRpcRequest(QStringLiteral("autostart.get"), QJsonObject());
    }
    Q_INVOKABLE QString rpcAutostartToggle(bool enabled) {
        QJsonObject obj;
        obj.insert(QStringLiteral("enabled"), enabled);
        return emitRpcRequest(QStringLiteral("autostart.toggle"), obj);
    }

    /// Report whether the administrative console is already reachable by name
    /// from a newly started shell. Read-only — changes nothing. Answered by the
    /// launcher, which is the process running as the interactive user whose
    /// environment is being inspected.
    Q_INVOKABLE QString rpcConsolePathState() {
        return emitRpcRequest(QStringLiteral("local.console-path.state"),
                              QJsonObject());
    }

    /// Add the console's folder to the current user's PATH. Idempotent: a
    /// second call reports the folder is already there and writes nothing.
    Q_INVOKABLE QString rpcConsolePathRegister() {
        return emitRpcRequest(QStringLiteral("local.console-path.register"),
                              QJsonObject());
    }

    /// Generic `MutationSubmit`. Lets QML invoke the
    /// two-phase mutation pipeline for any `MutationKind` (rules-update,
    /// preset-import / -export, settings-export). `dryRun = true` runs
    /// the review/preview path and returns a confirmation token plus a
    /// `ReviewSummaryResponse`; `dryRun = false` requires the
    /// confirmation token from the dry-run response and executes the
    /// mutation. The kebab-case `mutationKind` matches the wire enum
    /// (`"rules-update"`, `"route-bindings-update"`, `"preset-import"`,
    /// `"preset-export"`, `"settings-export"`).
    Q_INVOKABLE QString rpcMutationSubmit(const QString &mutationKind,
                                          const QVariantMap &payload,
                                          bool dryRun,
                                          const QString &confirmationToken) {
        QJsonObject obj;
        obj.insert(QStringLiteral("mutation-kind"), mutationKind);
        obj.insert(QStringLiteral("payload"),
                   QJsonObject::fromVariantMap(payload));
        obj.insert(QStringLiteral("dry-run"), dryRun);
        if (!confirmationToken.isEmpty()) {
            // Token must travel at envelope root, not payload root. The
            // launcher's build_request_envelope
            // promotes payload["_envelope_confirmation_token"] into
            // envelope["confirmation-token"]; putting it as a plain
            // "confirmation-token" payload field silently dropped it,
            // and the server returned PreconditionFailed because no
            // token reached the dispatcher.
            obj.insert(QStringLiteral("_envelope_confirmation_token"),
                       confirmationToken);
        }
        return emitRpcRequest(QStringLiteral("mutation.submit"), obj);
    }

    // Safe rollback: restore the previous (LKG) policy revision via the
    // `RollbackRequest` recovery action. `targetRevisionId` empty → roll back to
    // the last-known-good. Class = recovery-action (derived from the op slug by
    // the client), which requires a non-empty confirmation token + elevation;
    // the token travels at the envelope root via `_envelope_confirmation_token`.
    Q_INVOKABLE QString rpcRollbackRequest(const QString &targetRevisionId,
                                           const QString &confirmationToken) {
        QJsonObject obj;
        if (!targetRevisionId.isEmpty()) {
            obj.insert(QStringLiteral("target-revision-id"), targetRevisionId);
        }
        if (!confirmationToken.isEmpty()) {
            obj.insert(QStringLiteral("_envelope_confirmation_token"), confirmationToken);
        }
        return emitRpcRequest(QStringLiteral("rollback.request"), obj);
    }

    /// Typed `ProductImpactDisableTemporary` invocation. Two-phase:
    /// `dryRun=true` returns a
    /// `ProductImpactDisableDryRunResponse` (review summary + risk
    /// level + confirmation token). The caller then re-invokes with
    /// `dryRun=false` AND the token; the service consumes the token
    /// and executes `safe_disable`. Returns the correlation id so
    /// QML can register an `rpcResponse` callback.
    ///
    /// Token transport: the launcher's IPC client expects the
    /// confirmation-token at the envelope ROOT, not inside the
    /// payload. We smuggle it through the payload's
    /// `_envelope_confirmation_token` key — the client strips and
    /// promotes (see `build_request_envelope` in
    /// `core/ipc-client/src/client.rs`). This avoids a new
    /// `call_with_token` overload on the `IpcClient` trait.
    Q_INVOKABLE QString rpcProductImpactDisable(const QString &reason,
                                                bool dryRun,
                                                const QString &confirmationToken) {
        QJsonObject obj;
        obj.insert(QStringLiteral("reason"), reason);
        obj.insert(QStringLiteral("dry-run"), dryRun);
        if (!confirmationToken.isEmpty()) {
            obj.insert(QStringLiteral("_envelope_confirmation_token"),
                       confirmationToken);
        }
        return emitRpcRequest(
            QStringLiteral("product-impact.disable.temporary"), obj);
    }

    /// Read-only preset export. Calls
    /// `preset.export.get` and returns the correlation id; QML routes
    /// the `rpcResponse` callback to decode `file-bytes-b64` +
    /// `content-hash`. `route` is the kebab slug (`"primary"` /
    /// `"secondary"`); `includeMetadata` toggles the
    /// `# NetRuleRouter preset — version 1` preamble on the resulting
    /// txt blob.
    Q_INVOKABLE QString rpcPresetExport(const QString &route,
                                        bool includeMetadata) {
        QJsonObject obj;
        obj.insert(QStringLiteral("route"), route);
        obj.insert(QStringLiteral("include-metadata"), includeMetadata);
        return emitRpcRequest(QStringLiteral("preset.export.get"), obj);
    }

    /// Read-only full settings export. Calls
    /// `settings.export.full` and returns the correlation id. The
    /// server-owned bits (adapters + behavior mode) come from per-SID
    /// state; the two `rulesFilePath*` arguments forward the GUI's
    /// `UiPreferences::last_saved_path_<role>` so the YAML's
    /// `rules_files:` block carries the user's chosen on-disk paths.
    /// Empty strings ⇒ corresponding field omitted from the payload.
    Q_INVOKABLE QString rpcSettingsExportFull(
        const QString &rulesFilePathPrimary,
        const QString &rulesFilePathSecondary) {
        QJsonObject obj;
        if (!rulesFilePathPrimary.isEmpty()) {
            obj.insert(QStringLiteral("rules-file-path-primary"),
                       rulesFilePathPrimary);
        }
        if (!rulesFilePathSecondary.isEmpty()) {
            obj.insert(QStringLiteral("rules-file-path-secondary"),
                       rulesFilePathSecondary);
        }
        return emitRpcRequest(QStringLiteral("settings.export.full"), obj);
    }

    /// Read a file from disk and return its content
    /// base64-wrapped. Used by the GUI's `Qt.labs.platform.FileDialog`
    /// Open path to ferry preset bytes through `rpcMutationSubmit`'s
    /// JSON payload.
    ///
    /// Returns empty string on any error (missing file, permission
    /// denied, file > `IPC_MAX_MESSAGE_BYTES`). The 1 MiB cap mirrors
    /// the IPC frame ceiling so a too-large payload fails at the
    /// dialog rather than silently truncating downstream.
    ///
    /// Errors are logged to stderr; the GUI surfaces a toast based on
    /// the empty return.
    Q_INVOKABLE QString readFileBytes(const QString &path) {
        constexpr qint64 MAX_BYTES = 1024 * 1024;
        QFile file(path);
        if (!file.exists()) {
            qWarning() << "readFileBytes: file does not exist:" << path;
            return QString();
        }
        if (file.size() > MAX_BYTES) {
            qWarning() << "readFileBytes: file exceeds 1 MiB cap:" << path
                       << "size=" << file.size();
            return QString();
        }
        if (!file.open(QIODevice::ReadOnly)) {
            qWarning() << "readFileBytes: open failed:" << path
                       << "reason=" << file.errorString();
            return QString();
        }
        const QByteArray bytes = file.readAll();
        return QString::fromLatin1(bytes.toBase64());
    }

    /// Synchronous file metadata probe used by the
    /// drift detector's 30 s poll. Returns `{exists, size, mtime}`
    /// where `mtime` is Unix epoch seconds (QFileInfo's lastModified
    /// granularity is filesystem-dependent — NTFS resolves to ~100ns
    /// internally; we coarsen to seconds since drift polling only
    /// fires every 30 s anyway).
    ///
    /// Synchronous on purpose — `QFileInfo` is a thin wrapper around
    /// the OS stat call (microseconds on a warm cache), so threading
    /// it through the async RPC dispatcher would add overhead with no
    /// benefit. The QML caller awaits the return value directly.
    Q_INVOKABLE QVariantMap statFile(const QString &path) {
        QVariantMap out;
        if (path.isEmpty()) {
            out.insert(QStringLiteral("exists"), false);
            out.insert(QStringLiteral("size"), 0);
            out.insert(QStringLiteral("mtime"), 0);
            return out;
        }
        const QFileInfo info(path);
        if (!info.exists() || !info.isFile()) {
            out.insert(QStringLiteral("exists"), false);
            out.insert(QStringLiteral("size"), 0);
            out.insert(QStringLiteral("mtime"), 0);
            return out;
        }
        out.insert(QStringLiteral("exists"), true);
        out.insert(QStringLiteral("size"), info.size());
        out.insert(QStringLiteral("mtime"),
                   static_cast<qint64>(info.lastModified().toSecsSinceEpoch()));
        return out;
    }

    /// Async wrapper over the launcher-local
    /// `local.canonical-rules-hash` RPC. Returns a correlation id;
    /// QML registers a callback that lands on `rpcResponse` with the
    /// `{hash, canonical-bytes}` payload (see local_handlers.rs).
    Q_INVOKABLE QString rpcCanonicalRulesHash(const QString &rulesJson) {
        QJsonObject obj;
        obj.insert(QStringLiteral("rules-json"), rulesJson);
        return emitRpcRequest(QStringLiteral("local.canonical-rules-hash"),
                              obj);
    }

    /// Async wrapper over the launcher-local
    /// `local.vpn.discover` RPC. Scans the machine (running processes +
    /// installed programs) for likely VPN clients; the callback lands on
    /// `rpcResponse` with `{candidates:[{displayName, exePath, running,
    /// source}]}`. Local + non-elevated + no service needed, so onboarding
    /// works before the service is installed.
    Q_INVOKABLE QString rpcVpnDiscover() {
        return emitRpcRequest(QStringLiteral("local.vpn.discover"),
                              QJsonObject());
    }

    /// Async wrapper over the launcher-local
    /// `local.app-groups.discover` RPC. Scans the machine (running processes +
    /// installed programs + kernel-NAT service features) for known application
    /// groups (VMs/emulators + torrents/P2P). The callback lands on
    /// `rpcResponse` with `{apps:[{kind, displayName, exePath, running,
    /// source}]}`. Local + non-elevated + no service needed, so the route-
    /// assignment onboarding works before the service is installed.
    Q_INVOKABLE QString rpcAppGroupsDiscover() {
        return emitRpcRequest(QStringLiteral("local.app-groups.discover"),
                              QJsonObject());
    }

    /// Async wrapper over the service `diagnostics.seed-from-browser-history`
    /// RPC. On-demand, explicit-consent import: the service reads the local
    /// browser history and resolves ONLY the hosts that match the user's
    /// rules (privacy boundary), closing the cache gap for sites visited
    /// before the service was running. The callback lands on `rpcResponse`
    /// with `{started: true|false}` — no payload on the request.
    Q_INVOKABLE QString rpcSeedFromBrowserHistory() {
        return emitRpcRequest(QStringLiteral("diagnostics.seed-from-browser-history"),
                              QJsonObject());
    }

    /// Async wrapper over `local.service-info` RPC.
    /// Returns the GUI/service version + protocol pair so the
    /// compatibility banner can render "Service X.Y.Z (vN), App
    /// A.B.C (vM)". QML calls this on cold-start and on every
    /// disconnect→connect transition.
    Q_INVOKABLE QString rpcServiceInfo() {
        return emitRpcRequest(QStringLiteral("local.service-info"),
                              QJsonObject());
    }

    /// Return the OS user's default locale as a
    /// lowercase ISO-639 / ISO-3166 string ("ru_ru", "en_us", "zh_cn").
    /// Used by the first-launch wizard to suggest a country preset.
    /// The country code (after the underscore) maps directly to a
    /// folder under `presets/<cc>/`.
    Q_INVOKABLE QString detectOsLocale() {
        return QLocale::system().name().toLower();
    }

    /// List the bundled country-preset pack names
    /// for `countryCode` (lowercase 2-letter ISO, e.g. "ru", "cn").
    /// Returns a JSON array of strings (pack-folder names) so the
    /// wizard can render a chooser when multiple packs are available.
    /// Empty array when no folder exists for `countryCode`.
    ///
    /// The preset root is resolved by walking up from the binary's
    /// directory until a `presets/` folder is found — matches the
    /// `findUpwardFile` strategy used for QML asset resolution.
    Q_INVOKABLE QString listCountryPresets(const QString &countryCode) {
        const QString cc = countryCode.trimmed().toLower();
        if (cc.isEmpty()) {
            return QStringLiteral("[]");
        }
        const QString presetsRoot = findPresetsRoot();
        if (presetsRoot.isEmpty()) {
            qWarning() << "listCountryPresets: could not locate presets/ root";
            return QStringLiteral("[]");
        }
        const QDir countryDir(QDir(presetsRoot).filePath(cc));
        if (!countryDir.exists()) {
            return QStringLiteral("[]");
        }
        QJsonArray packs;
        const QStringList entries = countryDir.entryList(
            QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
        for (const QString &name : entries) {
            // Only emit packs that actually contain at least one of
            // the two preset files. Skips empty / README-only dirs.
            QDir packDir(countryDir.filePath(name));
            if (packDir.exists("rules_primary.txt")
                    || packDir.exists("rules_secondary.txt")) {
                packs.append(name);
            }
        }
        return QJsonDocument(packs).toJson(QJsonDocument::Compact);
    }

    /// Enumerate EVERY bundled preset across
    /// all country dirs under presets/. Returns a JSON array of
    /// {"country","pack","label":"<cc>_<pack>"} for packs that contain at
    /// least one rules file. Powers the rules-section "Load bundled preset"
    /// dropdown (country_pack → fill primary/secondary).
    ///
    /// `rootOverride` repoints the enumeration at a folder the
    /// user owns (Settings -> Presets). When it is non-empty and exists, that
    /// folder REPLACES the shipped tree; an empty / missing override keeps the
    /// shipped behaviour. An empty result is reported honestly so the caller
    /// can fall back and tell the user the folder holds no rule sets.
    Q_INVOKABLE QString listAllPresets(const QString &rootOverride = QString()) {
        const QString userRoot = rootOverride.trimmed();
        if (!userRoot.isEmpty()) {
            const QDir userDir(userRoot);
            if (!userDir.exists()) {
                qWarning() << "listAllPresets: user rule-set folder missing:" << userRoot;
                return QStringLiteral("[]");
            }
            return listUserPresets(userDir);
        }
        const QString presetsRoot = findPresetsRoot();
        if (presetsRoot.isEmpty()) {
            qWarning() << "listAllPresets: could not locate presets/ root";
            return QStringLiteral("[]");
        }
        QJsonArray out;
        const QDir root(presetsRoot);
        const QStringList countries =
            root.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
        for (const QString &cc : countries) {
            const QDir countryDir(root.filePath(cc));
            const QStringList packs =
                countryDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
            for (const QString &pack : packs) {
                QDir packDir(countryDir.filePath(pack));
                if (packDir.exists("rules_primary.txt")
                        || packDir.exists("rules_secondary.txt")) {
                    QJsonObject o;
                    o.insert(QStringLiteral("country"), cc);
                    o.insert(QStringLiteral("pack"), pack);
                    o.insert(QStringLiteral("label"), cc + QStringLiteral("_") + pack);
                    out.append(o);
                }
            }
        }
        return QJsonDocument(out).toJson(QJsonDocument::Compact);
    }

    /// Resolve the absolute path of a bundled preset
    /// file. `relativePath` is `<country>/<pack>/rules_<role>.txt` or
    /// `builtin-demo/rules_<role>.txt`. Returns empty string when the
    /// file is not found. Used by the wizard + Apply-demo flow to
    /// read built-in preset content via `readFileBytes`.
    ///
    /// `rootOverride` mirrors `listAllPresets`: when non-empty it
    /// is the ONLY root consulted, so a set that exists in the user's folder is
    /// never silently satisfied by a same-named shipped file.
    Q_INVOKABLE QString resolvePresetPath(const QString &relativePath,
                                          const QString &rootOverride = QString()) {
        if (relativePath.isEmpty()) {
            return QString();
        }
        const QString userRoot = rootOverride.trimmed();
        if (!userRoot.isEmpty()) {
            const QDir userDir(userRoot);
            if (userDir.exists()) {
                const QString p = userDir.filePath(relativePath);
                if (QFile::exists(p)) {
                    return p;
                }
            }
            // A set with only one of the two files is normal, so this is not
            // worth a warning — the caller reports "nothing readable" once.
            return QString();
        }
        // Try presets/<relativePath> first (country packs).
        const QString presetsRoot = findPresetsRoot();
        if (!presetsRoot.isEmpty()) {
            const QString p = QDir(presetsRoot).filePath(relativePath);
            if (QFile::exists(p)) {
                return p;
            }
        }
        // Fall back to configs/presets/<relativePath> (builtin-demo).
        const QString configsRoot = findConfigsPresetsRoot();
        if (!configsRoot.isEmpty()) {
            const QString p = QDir(configsRoot).filePath(relativePath);
            if (QFile::exists(p)) {
                return p;
            }
        }
        qWarning() << "resolvePresetPath: not found:" << relativePath;
        return QString();
    }

    /// Compute the default writable path for a per-user
    /// preset file. Returns `%LOCALAPPDATA%/NetRuleRouter/<filename>`.
    /// Creates the parent directory if missing. Empty string on error.
    Q_INVOKABLE QString defaultLocalAppDataPath(const QString &filename) {
        if (filename.isEmpty()) {
            return QString();
        }
        const QString base = QStandardPaths::writableLocation(
            QStandardPaths::AppLocalDataLocation);
        if (base.isEmpty()) {
            qWarning() << "defaultLocalAppDataPath: AppLocalDataLocation empty";
            return QString();
        }
        QDir dir(base);
        if (!dir.exists() && !dir.mkpath(".")) {
            qWarning() << "defaultLocalAppDataPath: mkpath failed for" << base;
            return QString();
        }
        return dir.filePath(filename);
    }

private:
    /// Find the workspace `presets/` directory (country
    /// packs). Empty string if no such directory exists in any parent
    /// of the binary location.
    ///
    /// Walks upward from the binary directory first; when that fails
    /// (typical with `[build] target-dir` pointing to a different drive
    /// than the source tree) falls back to the CMake-baked absolute
    /// path. Same strategy as `resolveQmlPath`.
    QString findPresetsRoot() const {
        const QString upward =
            findUpwardFile(applicationDir_, QStringLiteral("presets"));
        if (!upward.isEmpty()) { return upward; }
#if defined(NRR_PRESETS_ROOT_DEFAULT)
        const QString baked = QStringLiteral(NRR_PRESETS_ROOT_DEFAULT);
        if (!baked.isEmpty() && QFileInfo::exists(baked)) {
            return baked;
        }
#endif
        return QString();
    }

    /// Enumerate the rule sets in a folder the user owns. Their
    /// layout is flatter than the shipped country tree, so two shapes are
    /// accepted:
    ///   * one subfolder per set — `<root>/<set>/rules_primary.txt` — reported
    ///     as one entry per subfolder, `pack` = folder name;
    ///   * a single set at the root — `<root>/rules_primary.txt` — reported as
    ///     one entry named after the folder itself, with an empty `pack`.
    /// The root-level shape is only considered when no subfolder qualifies, so
    /// a folder holding both keeps the richer per-subfolder listing.
    ///
    /// `country` stays empty for user sets (there is nothing to infer a region
    /// from), which is also what keeps the label free of a `cc_` prefix.
    QString listUserPresets(const QDir &root) const {
        QJsonArray out;
        const QStringList sets =
            root.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
        for (const QString &name : sets) {
            QDir setDir(root.filePath(name));
            if (setDir.exists("rules_primary.txt")
                    || setDir.exists("rules_secondary.txt")) {
                QJsonObject o;
                o.insert(QStringLiteral("country"), QString());
                o.insert(QStringLiteral("pack"), name);
                o.insert(QStringLiteral("label"), name);
                out.append(o);
                continue;
            }
            // One level deeper, so pointing the folder at the sets shipped
            // with the app (or at any copy of that tree) lists them instead of
            // reading as empty: those live at `<country>/<pack>/rules_*.txt`.
            const QStringList packs =
                setDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
            for (const QString &pack : packs) {
                QDir packDir(setDir.filePath(pack));
                if (!packDir.exists("rules_primary.txt")
                        && !packDir.exists("rules_secondary.txt")) {
                    continue;
                }
                QJsonObject o;
                o.insert(QStringLiteral("country"), name);
                o.insert(QStringLiteral("pack"), pack);
                o.insert(QStringLiteral("label"),
                         name + QStringLiteral("_") + pack);
                out.append(o);
            }
        }
        if (out.isEmpty()
                && (root.exists("rules_primary.txt")
                    || root.exists("rules_secondary.txt"))) {
            const QString ownName = root.dirName();
            QJsonObject o;
            o.insert(QStringLiteral("country"), QString());
            o.insert(QStringLiteral("pack"), QString());
            o.insert(QStringLiteral("label"),
                     ownName.isEmpty() ? QStringLiteral("rules") : ownName);
            out.append(o);
        }
        return QJsonDocument(out).toJson(QJsonDocument::Compact);
    }

    /// Find the workspace `configs/presets/` directory
    /// (builtin demo + future configs-scoped packs). Separate from
    /// `presets/` because the country backlog lives at the repo root
    /// while the builtin demo is a config asset.
    QString findConfigsPresetsRoot() const {
        const QString upward =
            findUpwardFile(applicationDir_, QStringLiteral("configs/presets"));
        if (!upward.isEmpty()) { return upward; }
#if defined(NRR_CONFIGS_PRESETS_ROOT_DEFAULT)
        const QString baked = QStringLiteral(NRR_CONFIGS_PRESETS_ROOT_DEFAULT);
        if (!baked.isEmpty() && QFileInfo::exists(baked)) {
            return baked;
        }
#endif
        return QString();
    }

public:
    /// Write a file to disk from base64-encoded bytes.
    /// Used by the GUI's `Qt.labs.platform.FileDialog` Save path to
    /// persist the `file-bytes-b64` returned by `rpcPresetExport` or
    /// `rpcSettingsExportFull`.
    ///
    /// Returns `true` on success, `false` on any error (invalid
    /// base64, permission denied, parent directory missing). The 1 MiB
    /// cap is enforced symmetrically with `readFileBytes`.
    /// Write a UTF-8 text file directly.
    /// Used by the local canonical-txt writer for preset export so the
    /// QML side doesn't have to base64-encode Cyrillic / IDN text just
    /// to immediately decode it again. Same 1 MiB cap as the bytes path.
    Q_INVOKABLE bool writeTextFile(const QString &path, const QString &text) {
        constexpr qint64 MAX_BYTES = 1024 * 1024;
        const QByteArray utf8 = text.toUtf8();
        if (utf8.size() > MAX_BYTES) {
            qWarning() << "writeTextFile: payload exceeds 1 MiB cap:" << path
                       << "size=" << utf8.size();
            return false;
        }
        QFile f(path);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            qWarning() << "writeTextFile: open failed:" << path
                       << "error=" << f.errorString();
            return false;
        }
        const qint64 written = f.write(utf8);
        f.close();
        return written == utf8.size();
    }

    /// The absolute path of the rule sets shipped with the app,
    /// so the user can point their own folder at them (to copy a set and edit
    /// it) without hunting for the install directory. Empty when the tree
    /// cannot be located.
    Q_INVOKABLE QString bundledPresetsRoot() {
        return findPresetsRoot();
    }

    /// True when `path` resolves inside either bundled preset
    /// tree (`presets/<country>/<pack>/...` or
    /// `configs/presets/builtin-demo/...`). Both trees ship inside the
    /// app/repo and are read-only sources; the GUI must never bind a "save to
    /// file" target there — doing so would silently write a user's rule
    /// edits back into the shipped `presets/` git tree. Comparison
    /// is on the canonicalized absolute path, case-insensitive (Windows
    /// filesystem), so `presets/../presets/x` and mixed-case drive letters
    /// still match.
    Q_INVOKABLE bool isPathUnderBundledPresets(const QString &path) {
        const QString trimmed = path.trimmed();
        if (trimmed.isEmpty()) {
            return false;
        }
        const QFileInfo info(trimmed);
        const QString canonical = info.exists()
            ? info.canonicalFilePath()
            : QDir::cleanPath(info.absoluteFilePath());
        if (canonical.isEmpty()) {
            return false;
        }
        const QStringList roots = { findPresetsRoot(), findConfigsPresetsRoot() };
        for (const QString &root : roots) {
            if (root.isEmpty()) {
                continue;
            }
            const QFileInfo rootInfo(root);
            const QString canonicalRoot = rootInfo.exists()
                ? rootInfo.canonicalFilePath()
                : QDir::cleanPath(rootInfo.absoluteFilePath());
            if (canonicalRoot.isEmpty()) {
                continue;
            }
            if (canonical.compare(canonicalRoot, Qt::CaseInsensitive) == 0) {
                return true;
            }
            if (canonical.startsWith(canonicalRoot + QLatin1Char('/'), Qt::CaseInsensitive)) {
                return true;
            }
        }
        return false;
    }

    /// Create `<root>/<setName>/` for "save the current rules as
    /// a new set" and return its absolute path (empty on failure).
    ///
    /// `setName` is a plain folder name, never a path: anything carrying a
    /// separator, a drive letter or `..` is refused rather than sanitised, so
    /// a name typed into the GUI can never write outside the folder the user
    /// chose. An existing set is reused (the caller confirms the overwrite).
    Q_INVOKABLE QString createPresetSetDir(const QString &rootDir,
                                           const QString &setName) {
        const QString root = rootDir.trimmed();
        const QString name = setName.trimmed();
        if (root.isEmpty() || name.isEmpty()) {
            return QString();
        }
        if (name.contains(QLatin1Char('/')) || name.contains(QLatin1Char('\\'))
                || name.contains(QLatin1Char(':')) || name == QStringLiteral(".")
                || name.contains(QStringLiteral(".."))) {
            qWarning() << "createPresetSetDir: refusing a name that is a path:"
                       << name;
            return QString();
        }
        QDir rootQDir(root);
        if (!rootQDir.exists()) {
            qWarning() << "createPresetSetDir: root does not exist:" << root;
            return QString();
        }
        const QString target = rootQDir.filePath(name);
        QDir targetDir(target);
        if (!targetDir.exists() && !rootQDir.mkpath(name)) {
            qWarning() << "createPresetSetDir: mkpath failed for" << target;
            return QString();
        }
        return target;
    }

    Q_INVOKABLE bool writeFileBytes(const QString &path,
                                    const QString &base64) {
        constexpr qint64 MAX_BYTES = 1024 * 1024;
        const QByteArray bytes = QByteArray::fromBase64(
            base64.toUtf8(), QByteArray::AbortOnBase64DecodingErrors);
        if (bytes.isEmpty() && !base64.isEmpty()) {
            qWarning() << "writeFileBytes: base64 decode failed for"
                       << path;
            return false;
        }
        if (bytes.size() > MAX_BYTES) {
            qWarning() << "writeFileBytes: payload exceeds 1 MiB cap:"
                       << path << "size=" << bytes.size();
            return false;
        }
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            qWarning() << "writeFileBytes: open failed:" << path
                       << "reason=" << file.errorString();
            return false;
        }
        const qint64 written = file.write(bytes);
        if (written != bytes.size()) {
            qWarning() << "writeFileBytes: short write to" << path
                       << "wrote=" << written << "of" << bytes.size();
            return false;
        }
        return true;
    }

    /// `StatusUpdatesSubscribe`. After a successful
    /// subscribe the launcher streams server-pushed events on stdin
    /// as `NRR_IPC_PUSH:<json>` lines; the `RpcStdinReader` thread
    /// parses them and emits `pushEvent(...)` on this bridge.
    /// `clientId` is a stable opaque token the GUI mints once per
    /// session (e.g. process id or a uuid-equivalent counter).
    Q_INVOKABLE QString rpcStatusUpdatesSubscribe(const QString &clientId) {
        QJsonObject obj;
        obj.insert(QStringLiteral("client-id"), clientId);
        return emitRpcRequest(QStringLiteral("status.updates.subscribe"), obj);
    }

    // ── Diagnostics + explain + service-stability ─────────────────────────
    //
    // The wire shapes live in `nrr_shared::ipc_payloads`. The launcher
    // dispatcher applies a per-op timeout budget (Explain=2s, Archive=10s,
    // ServiceStability=1s) automatically — these bridge methods only need to
    // mint the request envelope.

    /// `ExplainGet` by historical decision id. The service
    /// looks up the persisted `DecisionExplain` (when the snapshot
    /// store lands — until then it always returns `Unavailable`). The
    /// optional `detailLevel` slug is one of `"compact-ui"`,
    /// `"diagnostics"`, `"developer-trace"`; pass an empty string to
    /// accept the server default (`"compact-ui"`).
    Q_INVOKABLE QString rpcExplainGetByDecisionId(const QString &decisionId,
                                                   const QString &detailLevel) {
        QJsonObject obj;
        obj.insert(QStringLiteral("decision-id"), decisionId);
        if (!detailLevel.isEmpty()) {
            obj.insert(QStringLiteral("detail-level"), detailLevel);
        }
        return emitRpcRequest(QStringLiteral("diagnostics.explain.get"), obj);
    }

    /// `ExplainGet` for a synthetic probe — runs the
    /// decision engine against the active rule set without recording an
    /// audit event. At least one of `hostname` / `observedIp` /
    /// `processName` must be non-empty; the server rejects all-empty
    /// samples with `PreconditionFailed`.
    Q_INVOKABLE QString rpcExplainGetBySample(const QString &hostname,
                                               const QString &observedIp,
                                               const QString &processName,
                                               const QString &detailLevel) {
        QJsonObject sample;
        if (!hostname.isEmpty()) {
            sample.insert(QStringLiteral("hostname"), hostname);
        }
        if (!observedIp.isEmpty()) {
            sample.insert(QStringLiteral("observed-ip"), observedIp);
        }
        if (!processName.isEmpty()) {
            sample.insert(QStringLiteral("process-name"), processName);
        }
        QJsonObject obj;
        obj.insert(QStringLiteral("input-sample"), sample);
        if (!detailLevel.isEmpty()) {
            obj.insert(QStringLiteral("detail-level"), detailLevel);
        }
        return emitRpcRequest(QStringLiteral("diagnostics.explain.get"), obj);
    }

    /// `SnapshotInterfacesGet`. Lightweight read
    /// that returns `SnapshotInterfacesResponse` (`adapters`,
    /// `data_source`, optional `secondary: SecondaryRouteStateDto`).
    /// The GUI uses the `secondary.fail_closed_active` flag to drive
    /// the Fail-Closed banner in `InterfacesRoutesSection.qml`. The
    /// adapters array itself is still sourced from the cold-start
    /// snapshot bundle in production today; we don't replace it on
    /// every refresh to avoid stomping on the section's local sort /
    /// filter state.
    Q_INVOKABLE QString rpcSnapshotInterfacesGet() {
        return emitRpcRequest(QStringLiteral("snapshot.interfaces.get"),
                              QJsonObject());
    }

    /// Re-enumerate adapters AND probe each one's external address. Same
    /// response shape as `rpcSnapshotInterfacesGet`, but this one leaves the
    /// machine: the probe sends a packet per eligible adapter. It is therefore
    /// a deliberate, user-initiated action and must never be wired to an
    /// automatic refresh path.
    Q_INVOKABLE QString rpcInterfacesRefresh() {
        return emitRpcRequest(QStringLiteral("interfaces.refresh.request"),
                              QJsonObject());
    }

    /// `LogsList`. Paginated query for operational
    /// log entries. `filter` is a kebab-shaped subset of `LogEntryFilter`
    /// (the nested DTO itself is snake-case on the wire — `from_ms`,
    /// `level_min`, `decision_id`, `revision_id`); QML constructs the
    /// map verbatim using snake_case keys. `cursor` is the opaque
    /// `next-cursor` echoed back by the previous page (empty for first
    /// page). `pageSize <= 0` falls back to `PaginationParams::default()`
    /// server-side (50 entries).
    /// `LogsClear`. Removes rotated
    /// operational NDJSON files. Audit trail is never touched.
    /// `dryRun=true` returns counts without acting.
    Q_INVOKABLE QString rpcLogsClear(bool dryRun, bool includeArchives) {
        QJsonObject obj;
        obj.insert(QStringLiteral("dry-run"), dryRun);
        obj.insert(QStringLiteral("include-archives"), includeArchives);
        return emitRpcRequest(QStringLiteral("logs.clear"), obj);
    }

    // Enable/disable extended diagnostics for a bounded session. When
    // enabled, `untilRestart` overrides `durationMs`; `durationMs <= 0` uses the
    // service default (1h). Response is the resulting diagnostic-mode state.
    Q_INVOKABLE QString rpcDiagnosticModeSet(bool enabled, double durationMs,
                                             bool untilRestart, const QString &scope) {
        QJsonObject obj;
        obj.insert(QStringLiteral("enabled"), enabled);
        if (durationMs > 0) {
            obj.insert(QStringLiteral("duration-ms"), durationMs);
        }
        obj.insert(QStringLiteral("until-restart"), untilRestart);
        if (!scope.isEmpty()) {
            obj.insert(QStringLiteral("scope"), scope);
        }
        return emitRpcRequest(QStringLiteral("diagnostics.mode.set"), obj);
    }

    // Clear the rebuildable FQDN/IP resolution cache. `payload` is a full
    // CacheClearRequest ({dry-run?, clear-app-cache? (default true),
    // flush-os-cache? (default false)}) so the GUI can independently clear
    // the app cache and/or flush the OS DNS cache. Same pass-through style
    // as rpcRoutePolicyUpdate.
    Q_INVOKABLE QString rpcCacheClear(const QVariantMap &payload) {
        return emitRpcRequest(QStringLiteral("cache.clear"),
                              QJsonObject::fromVariantMap(payload));
    }

    // Read-only paginated view of the FQDN/IP resolution cache.
    // Mirrors rpcLogsList's paging shape: `cursor` is the opaque offset
    // cursor echoed back as `page.next_cursor` from the previous page
    // (empty for the first page); `pageSize <= 0` falls back to the
    // server-side PaginationParams default (50 entries). The response
    // carries `page.items` (CacheEntryDto) + `redacted` (compact tier).
    // `query` is an optional server-side search term: the service
    // filters the cache by a host/IP substring (WHERE LIKE) so a large cache is
    // searched in SQLite instead of drained page-by-page into the GUI. Empty =
    // no filter (full listing). Kept as a trailing arg so existing 2-arg callers
    // still compile; QML passes it positionally.
    Q_INVOKABLE QString rpcCacheEntriesList(const QString &cursor, int pageSize,
                                            const QString &query = QString()) {
        QJsonObject pagination;
        if (!cursor.isEmpty()) {
            pagination.insert(QStringLiteral("cursor"), cursor);
        }
        if (pageSize > 0) {
            pagination.insert(QStringLiteral("page_size"), pageSize);
        }
        QJsonObject obj;
        obj.insert(QStringLiteral("pagination"), pagination);
        if (!query.isEmpty()) {
            obj.insert(QStringLiteral("query"), query);
        }
        return emitRpcRequest(QStringLiteral("cache.entries.list"), obj);
    }

    // Read-only paginated view of recently-observed outbound connections.
    // Identical paging shape to rpcCacheEntriesList: `cursor` is the opaque
    // offset echoed back as `page.next_cursor`; `pageSize <= 0` uses the
    // server-side default. The response carries `page.items` (ConnTraceEntryDto:
    // process/proto/local/remote/egress-role/egress-ifindex/verdict) + `redacted`.
    Q_INVOKABLE QString rpcConnTraceEntriesList(const QString &cursor, int pageSize) {
        QJsonObject pagination;
        if (!cursor.isEmpty()) {
            pagination.insert(QStringLiteral("cursor"), cursor);
        }
        if (pageSize > 0) {
            pagination.insert(QStringLiteral("page_size"), pageSize);
        }
        QJsonObject obj;
        obj.insert(QStringLiteral("pagination"), pagination);
        return emitRpcRequest(QStringLiteral("conn-trace.entries.list"), obj);
    }

    // File↔service merge preview (SERVICE Query op). The service
    // reconciles the supplied bound-file text against the caller's active
    // revision (per-SID read-through) and returns the three buckets + conflicts
    // + merged rules-json. Called twice: first with an empty `resolutions`
    // array (buckets under Union), then again with the per-conflict picks
    // ({ "identity-key": ..., "side": "file"|"service" }) to get the final
    // merged rules-json for `startRulesReviewFlow`.
    Q_INVOKABLE QString rpcRulesMergePreview(const QString &primaryText,
                                             const QString &secondaryText,
                                             const QString &policySlug,
                                             const QVariantList &resolutions) {
        QJsonObject obj;
        obj.insert(QStringLiteral("primary-text"), primaryText);
        obj.insert(QStringLiteral("secondary-text"), secondaryText);
        obj.insert(QStringLiteral("policy"),
                   policySlug.isEmpty() ? QStringLiteral("union") : policySlug);
        obj.insert(QStringLiteral("resolutions"),
                   QJsonArray::fromVariantList(resolutions));
        return emitRpcRequest(QStringLiteral("rules.merge-preview"), obj);
    }

    Q_INVOKABLE QString rpcLogsList(const QVariantMap &filter,
                                     const QString &cursor,
                                     int pageSize) {
        QJsonObject pagination;
        if (!cursor.isEmpty()) {
            pagination.insert(QStringLiteral("cursor"), cursor);
        }
        if (pageSize > 0) {
            pagination.insert(QStringLiteral("page_size"), pageSize);
        }
        QJsonObject obj;
        obj.insert(QStringLiteral("filter"),
                   QJsonObject::fromVariantMap(filter));
        obj.insert(QStringLiteral("pagination"), pagination);
        return emitRpcRequest(QStringLiteral("logs.list"), obj);
    }

    /// `AuditList`. Same shape as `rpcLogsList`
    /// but with `AuditEntryFilter` semantics: `kind`, `alert_state`,
    /// `revision_id`, `from_ms`, `to_ms`. Service-side filtering is
    /// strict — unknown filter keys are ignored.
    Q_INVOKABLE QString rpcAuditList(const QVariantMap &filter,
                                      const QString &cursor,
                                      int pageSize) {
        QJsonObject pagination;
        if (!cursor.isEmpty()) {
            pagination.insert(QStringLiteral("cursor"), cursor);
        }
        if (pageSize > 0) {
            pagination.insert(QStringLiteral("page_size"), pageSize);
        }
        QJsonObject obj;
        obj.insert(QStringLiteral("filter"),
                   QJsonObject::fromVariantMap(filter));
        obj.insert(QStringLiteral("pagination"), pagination);
        return emitRpcRequest(QStringLiteral("audit.list"), obj);
    }

    /// `DiagnosticsExportArchive`. The service writes a
    /// zip into the per-user `archives/` directory inheriting the
    /// `Users:RX` ACL. The response carries the
    /// absolute path, byte size, and an epoch-ms generation timestamp.
    /// All inclusion flags default to `true` on the server when the
    /// request is empty; here we pass them explicitly so QML state is
    /// the source of truth.
    Q_INVOKABLE QString rpcDiagnosticsExportArchive(
        bool includeLogs,
        bool includeAuditSummary,
        bool includeTroubleshootingPlaybooks,
        const QString &redactionLevel = QString(),
        double logsFromMs = 0) {
        QJsonObject obj;
        obj.insert(QStringLiteral("include-logs"), includeLogs);
        obj.insert(QStringLiteral("include-audit-summary"), includeAuditSummary);
        obj.insert(QStringLiteral("include-troubleshooting-playbooks"),
                   includeTroubleshootingPlaybooks);
        // "Current session only" log trimming: UTC ms the
        // GUI session started; the service drops older logs.ndjson entries.
        // 0 (the QML default) means "no cutoff" and is not forwarded.
        if (logsFromMs > 0) {
            obj.insert(QStringLiteral("logs-from-ms"),
                       static_cast<qint64>(logsFromMs));
        }
        // Optional privacy tier: "standard" (default, redacted) or
        // "diagnostics" (extra cache/storage/decision detail, less redacted).
        // Absent/unknown resolves to standard on the server, so only forward a
        // non-empty selection.
        if (!redactionLevel.isEmpty()) {
            obj.insert(QStringLiteral("redaction-level"), redactionLevel);
        }
        return emitRpcRequest(QStringLiteral("diagnostics.export-archive"), obj);
    }

    /// `ServiceStabilityConfigGet`. Empty request, the
    /// response carries the currently-persisted `ServiceStabilityConfig`
    /// (or the canonical default if no row has been written yet).
    Q_INVOKABLE QString rpcServiceStabilityConfigGet() {
        return emitRpcRequest(
            QStringLiteral("settings.service-stability.get"), QJsonObject());
    }

    /// `ServiceStabilityConfigSet`. The recoverable
    /// variant requires all three numeric parameters; the critical
    /// variant takes none. The map shape mirrors the wire JSON:
    ///
    ///   { "ipc-accept-policy": {
    ///         "kind": "recoverable",
    ///         "max-restarts": 20,
    ///         "backoff-base-ms": 100,
    ///         "backoff-cap-ms": 5000 } }
    ///
    /// or
    ///
    ///   { "ipc-accept-policy": { "kind": "critical" } }
    ///
    /// The bridge passes the map through verbatim — QML is responsible
    /// for constructing the kebab-case keys and the cross-field
    /// constraint (recoverable ⇒ all three parameters; critical ⇒
    /// none). The service revalidates on the storage boundary and
    /// returns `PreconditionFailed` on mismatch.
    /// `origin` is an optional writer-attribution
    /// tag (e.g. "user:enforcement-mode") the service logs verbatim; moc
    /// generates an overload so existing one-argument QML callers keep
    /// working.
    Q_INVOKABLE QString rpcServiceStabilityConfigSet(const QVariantMap &config,
                                                     const QString &origin = QString()) {
        QJsonObject obj;
        obj.insert(QStringLiteral("config"),
                   QJsonObject::fromVariantMap(config));
        if (!origin.isEmpty())
            obj.insert(QStringLiteral("origin"), origin);
        return emitRpcRequest(
            QStringLiteral("settings.service-stability.set"), obj);
    }

    // ── Sidecar SQLite (GUI-only metadata) ──────────────────────────
    //
    // These operations are routed locally by the launcher; they never
    // reach the Windows service. Comments, foreign-OS passthrough
    // sections, and the "Work without service" pending-apply snapshot
    // all live in a per-user file at `%APPDATA%\NetRuleRouter\
    // gui_metadata.db` and are owned by the launcher process. See
    // `nrr-storage-sidecar` crate docs for the threat model and
    // privacy rationale.
    //
    // All return the correlation id immediately; the actual SQL runs
    // on a worker thread inside the launcher. QML callers route the
    // eventual `rpcResponse(...)` signal through `registerRpcCallback`.

    Q_INVOKABLE QString rpcSidecarCommentRead(const QString &type_,
                                              const QString &value,
                                              const QString &route) {
        QJsonObject obj;
        obj.insert(QStringLiteral("type"), type_);
        obj.insert(QStringLiteral("value"), value);
        obj.insert(QStringLiteral("route"), route);
        return emitRpcRequest(QStringLiteral("sidecar.comment.read"), obj);
    }

    /// Bulk read every stored comment in one RPC.
    /// Returned payload shape: `{ comments: { "<signature>": "<text>", ... } }`.
    /// QML builds the signature client-side via `_sidecarRuleSignature`
    /// and looks rows up; missing keys mean the rule has no comment.
    Q_INVOKABLE QString rpcSidecarCommentReadAll() {
        return emitRpcRequest(QStringLiteral("sidecar.comment.read-all"),
                              QJsonObject());
    }

    Q_INVOKABLE QString rpcSidecarCommentWrite(const QString &type_,
                                               const QString &value,
                                               const QString &route,
                                               const QString &comment) {
        QJsonObject obj;
        obj.insert(QStringLiteral("type"), type_);
        obj.insert(QStringLiteral("value"), value);
        obj.insert(QStringLiteral("route"), route);
        obj.insert(QStringLiteral("comment"), comment);
        return emitRpcRequest(QStringLiteral("sidecar.comment.write"), obj);
    }

    /// Pass an array of `{type, value, route}` objects.
    /// Any stored comment whose signature isn't in the array is dropped.
    Q_INVOKABLE QString rpcSidecarCommentGc(const QVariantList &activeSignatures) {
        QJsonArray arr;
        for (const QVariant &v : activeSignatures) {
            arr.append(QJsonObject::fromVariantMap(v.toMap()));
        }
        QJsonObject obj;
        obj.insert(QStringLiteral("active-signatures"), arr);
        return emitRpcRequest(QStringLiteral("sidecar.comment.gc"), obj);
    }

    Q_INVOKABLE QString rpcSidecarPassthroughRead(const QString &route) {
        QJsonObject obj;
        obj.insert(QStringLiteral("route"), route);
        return emitRpcRequest(QStringLiteral("sidecar.passthrough.read"), obj);
    }

    /// `sections` is a `{sectionName: rawText}` map.
    Q_INVOKABLE QString rpcSidecarPassthroughWrite(const QString &route,
                                                   const QVariantMap &sections) {
        QJsonObject obj;
        obj.insert(QStringLiteral("route"), route);
        obj.insert(QStringLiteral("sections"),
                   QJsonObject::fromVariantMap(sections));
        return emitRpcRequest(QStringLiteral("sidecar.passthrough.write"), obj);
    }

    Q_INVOKABLE QString rpcSidecarPendingApplyRead() {
        return emitRpcRequest(QStringLiteral("sidecar.pending-apply.read"),
                              QJsonObject());
    }

    Q_INVOKABLE QString rpcSidecarPendingApplyWrite(const QString &rulesJson,
                                                    const QString &summaryJson,
                                                    const QString &contentHash) {
        QJsonObject obj;
        obj.insert(QStringLiteral("rules-json"), rulesJson);
        obj.insert(QStringLiteral("summary-json"), summaryJson);
        obj.insert(QStringLiteral("content-hash"), contentHash);
        return emitRpcRequest(QStringLiteral("sidecar.pending-apply.write"), obj);
    }

    Q_INVOKABLE QString rpcSidecarPendingApplyClear() {
        return emitRpcRequest(QStringLiteral("sidecar.pending-apply.clear"),
                              QJsonObject());
    }

    /// Bulk read every cached last-known external IP in one RPC.
    /// Returned payload shape: `{ entries: { "<adapter-key>":
    /// {"external-ip": "...", "observed-at-ms": ...}, ... } }`.
    Q_INVOKABLE QString rpcSidecarExternalIpReadAll() {
        return emitRpcRequest(QStringLiteral("sidecar.external-ip.read-all"),
                              QJsonObject());
    }

    /// `entries` is an array of `{key, external-ip, observed-at-ms}`
    /// objects — one per adapter whose external address the service
    /// just resolved.
    Q_INVOKABLE QString rpcSidecarExternalIpWriteAll(const QVariantList &entries) {
        QJsonArray arr;
        for (const QVariant &v : entries) {
            arr.append(QJsonObject::fromVariantMap(v.toMap()));
        }
        QJsonObject obj;
        obj.insert(QStringLiteral("entries"), arr);
        return emitRpcRequest(QStringLiteral("sidecar.external-ip.write-all"), obj);
    }

    /// `force = true` skips the size/interval throttle and vacuums
    /// immediately (used by Settings → "Reset application data").
    Q_INVOKABLE QString rpcSidecarVacuum(bool force) {
        QJsonObject obj;
        obj.insert(QStringLiteral("force"), force);
        return emitRpcRequest(QStringLiteral("sidecar.vacuum"), obj);
    }

    /// Full reset: wipe every GUI-local
    /// sidecar row (rule comments, foreign-OS passthrough, parked
    /// pending-apply). Async launcher-local op; QML registers a callback
    /// on the returned correlation id.
    Q_INVOKABLE QString rpcSidecarReset() {
        return emitRpcRequest(QStringLiteral("sidecar.reset"), QJsonObject());
    }

    // ── Canonical-txt parser RPC ────────────────────────────────────
    //
    // Routed through the launcher's local handler (no service hop);
    // the parser itself lives in `nrr_shared::preset_parser`. QML
    // receives the structured `PresetParseResult` JSON inside the
    // response `payload.result` field and translates it back to
    // rulesModel rows, including the Punycode -> Unicode boundary
    // conversion.
    /// Parse a canonical txt body. `text` must be UTF-8 decoded
    /// already — typically obtained via `decodeBase64Utf8` against
    /// `readFileBytes`. Returns the correlation id; QML registers a
    /// callback through `registerRpcCallback`.
    Q_INVOKABLE QString rpcPresetParse(const QString &text) {
        QJsonObject obj;
        obj.insert(QStringLiteral("text"), text);
        return emitRpcRequest(QStringLiteral("preset.parse"), obj);
    }

signals:
    /// Emitted on the GUI thread when a `NRR_IPC_PUSH:` line arrives.
    /// `event` is the `StatusUpdateEvent` JSON object (kebab-case;
    /// `type` discriminator + variant-specific fields). QML
    /// dispatches by `event.type`.
    void pushEvent(QString subscriptionId, qint64 eventId, QVariant event);

public:

    /// Invoked by `RpcStdinReader` (different thread)
    /// when a `NRR_IPC_RESPONSE:` line arrives. Marshals to the GUI
    /// thread via `QMetaObject::invokeMethod(... Qt::QueuedConnection)`.
    Q_INVOKABLE void deliverRpcResponse(const QString &line) {
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

    /// Programmatic check used by Tray.qml stub. Returns
    /// `true` once at least one RPC round-trip has succeeded; lets the
    /// tray stop showing a "service unreachable" banner.
    Q_INVOKABLE bool hasRpcChannel() const { return rpcResponseCount_.load() > 0; }

    /// Invoked by `RpcStdinReader` when a `NRR_IPC_PUSH:`
    /// line arrives. Marshals to GUI thread via QueuedConnection;
    /// parses the envelope and emits `pushEvent(...)`.
    Q_INVOKABLE void deliverPushEvent(const QString &line) {
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

private:
    QString emitRpcRequest(const QString &operation, const QJsonObject &payload) {
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

    static QString stripPrefix(const QString &s, const QString &prefix) {
        if (s.startsWith(prefix)) {
            return s.mid(prefix.size());
        }
        return s;
    }

public:
    /// Called by `RpcStdinReader` after each successfully-delivered
    /// response. The counter is observed by `hasRpcChannel()`.
    void incrementRpcResponseCount() { rpcResponseCount_.fetch_add(1); }

    // QML-side child Windows (About, License, dialogs, first-run wizard)
    // have their own native title bars and need the same DWM toggle as the
    // main window. Accepts any QObject so QML can pass `Window { id: ... }`.
    Q_INVOKABLE void setWindowDarkTitleBar(QObject *qmlWindow, bool dark) {
        applyDarkTitleBarToWindow(qobject_cast<QWindow *>(qmlWindow), dark);
    }

private:
    static void applyDarkTitleBarToWindow(QWindow *window, bool dark) {
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

    void launchMainGui(const QString &section, bool about, bool license) {
        launchMainGuiWithAction(section, about, license, {}, {});
    }

    // Extended launcher hand-off. `action` carries an intent slug consumed by
    // the primary GUI's `applyGuiActivationRequest` (`"safe-disable"`,
    // `"rules-drift-apply"`); `reason`
    // is an operator-provided justification accompanying the action.
    // Both arguments are optional — when empty they're omitted from
    // the CLI and the launcher falls back to a plain section-switch.
    void launchMainGuiWithAction(const QString &section, bool about, bool license,
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

    void openLogsFolder() {
        if (logsDirectory_.isEmpty()) {
            qWarning() << "Logs directory was not resolved.";
            return;
        }
#ifdef Q_OS_WIN
        if (!QProcess::startDetached(QStringLiteral("explorer.exe"), {QDir::toNativeSeparators(logsDirectory_)})) {
            qWarning() << "Failed to open logs folder via explorer.exe.";
        }
#else
        QDesktopServices::openUrl(QUrl::fromLocalFile(logsDirectory_));
#endif
    }

    // ── Tray liveness watch ──────────────────────────────────────────────
    //
    // Pure process plumbing: the tray is started detached, so it is not a
    // child of this process and the OS never notifies us when it goes away.
    // A low-frequency poll of the PID `startDetached` handed back is the
    // cheapest way to notice. The decision of what to DO about it stays in
    // QML (it owns the wind-down routine) — this only reports the fact.
    //
    // Arming rule: a duplicate `NetRuleRouterTray.exe` launch is a no-op in
    // the launcher (the single-instance lock is held by the tray already
    // running) and exits within milliseconds. Such a PID must never be
    // mistaken for a dying tray, so the watch only arms after the PID has
    // been seen ALIVE at least once.
    //
    // Observation window: a single inconclusive or negative probe is NOT a
    // verdict. The watch keeps polling for `kTrayStartupObservationWindowMs`
    // and only goes idle if that whole window passed without one positive
    // observation — the alternative (deciding on the first poll) turns any
    // transient probe failure into a permanently disarmed watch.
    void watchTrayProcess(qint64 pid) {
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

    void pollTrayLiveness() {
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

    /// Outcome of one liveness probe. `Unknown` exists so that an OS that
    /// refuses to answer can never be mistaken for a dead process.
    enum class ProcessLiveness { Alive, Gone, Unknown };

    static ProcessLiveness probeProcessLiveness(qint64 pid,
                                                quint32 *osErrorOut = nullptr) {
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

    QString applicationDir_;
    QString mainQmlPath_;
    QString mainGuiExecutable_;
    QString mainGuiBackendExecutable_;
    QString trayGuiExecutable_;
    QString guiActivationRequestPath_;
    QString logsDirectory_;
    QWindow *mainWindow_ = nullptr;
    /// Monotonic correlation-id counter for RPC requests.
    std::atomic<quint64> rpcCorrelationCounter_{0};
    /// Count of successfully-delivered RPC responses.
    /// Observed by `hasRpcChannel()` to drive a "channel ready" hint.
    std::atomic<quint64> rpcResponseCount_{0};
    /// Single-entry cache for `prepareTrayGrayscaleIcon`.
    /// Key is the source URL the QML last asked about; value is the
    /// path to the cached PNG. Re-rendering on every push event would
    /// thrash the disk for no reason.
    QString grayscaleIconCacheSource_;
    QString grayscaleIconCachePath_;
    /// Single-entry cache for `prepareTrayStatusIcon`.
    /// Key is `sourceUrl + ":" + statusKind` so a status flip
    /// re-renders, but consecutive identical calls hit cache.
    QString statusIconCacheKey_;
    QString statusIconCachePath_;
    /// Tray liveness watch state (see `watchTrayProcess`). `trayProcessId_`
    /// is the PID `QProcess::startDetached` returned for the tray launcher we
    /// spawned; 0 means "nothing to watch" (tray started by someone else, or
    /// the watch already settled).
    qint64 trayProcessId_ = 0;
    bool trayProcessConfirmedAlive_ = false;
    bool trayDeathReported_ = false;
    bool trayLivenessTimerConnected_ = false;
    /// Latched once an intentional exit has passed through this bridge
    /// (tray "Exit" consumed, full reset requested, application quitting).
    /// The shutdown flags are deleted by whoever consumes them, so the file
    /// check alone races with the process actually going away.
    bool trayShutdownExpected_ = false;
    /// Diagnostics for the startup observation window — reported verbatim in
    /// `NRR_HOST_TRAY_WATCH_IDLE` so a run can be triaged from the log alone.
    int trayLivenessPollCount_ = 0;
    int trayLivenessGoneObservations_ = 0;
    quint32 trayLivenessLastOsError_ = 0;
    bool trayLivenessInconclusiveLogged_ = false;
    QElapsedTimer trayWatchElapsed_;
    QTimer trayLivenessTimer_;
    static constexpr int kTrayLivenessPollIntervalMs = 2000;
    /// How long the tray gets to show up as a live process before the watch
    /// gives up. Measured cold starts (debug build) are ~3 s from spawn to the
    /// tray's QML being loaded and ~7 s for the main GUI's own chain; this is
    /// several times that, so a loaded machine still fits, while a genuine
    /// duplicate-launch no-op only delays a log line nobody waits for.
    static constexpr int kTrayStartupObservationWindowMs = 30000;
};

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
//   - operationCompleted(operation, success, errorMessage): emitted at
//     the end of every async install/uninstall/start/stop.
//   - uacDeclined(operation): emitted when `ShellExecuteExW` returned
//     `FALSE` with `GetLastError() == ERROR_CANCELLED` (1223). QML
//     uses this to record the decline in `prefs.serviceInstallUacDeclined*`
//     and downgrade re-prompting to a passive banner.
//
// The service binary path is resolved at construction via the same
// `findUpwardFile` helper that QML/icons use — works for both dev
// (`target/<profile>/nrr-service.exe`) and production install
// (`%ProgramFiles%\NetRuleRouter\nrr-service.exe` with the GUI binary
// one directory up).

// True when THIS process already carries an elevated
// (high-integrity admin) token. When already elevated, a child launched
// with the default shell verb inherits our token with NO extra UAC
// prompt; only a non-elevated process needs the `runas` verb (which
// raises UAC). Used by the service worker so "Run as administrator" users
// don't get re-prompted on every service operation.
static bool nrrProcessIsElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elevation{};
    DWORD bytes = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation,
                                        &elevation, sizeof(elevation), &bytes);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

class NrrServiceWorker : public QObject {
    Q_OBJECT
public:
    explicit NrrServiceWorker(QObject *parent = nullptr) : QObject(parent) {}

public slots:
    /// Invokes `<servicePath> <command>` via `ShellExecuteExW` with the
    /// `runas` verb, waits up to 30 s for completion, and emits
    /// `result(operation, success, errorMessage)` on the controller's
    /// signal slot.
    void runElevated(const QString &operation,
                     const QString &servicePath,
                     const QString &command) {
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

        const DWORD wait = WaitForSingleObject(sei.hProcess, 30000);
        if (wait != WAIT_OBJECT_0) {
            CloseHandle(sei.hProcess);
            emit result(operation, false,
                        QStringLiteral("Timed out waiting for service operation"));
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
                                  QObject *parent = nullptr)
        : QObject(parent) {
        // The service executable is `nrr-service.exe` on every layout —
        // the crate name states the platform, the binary name states the
        // role. Dev paths first (target/debug, target/release), then
        // sibling-to-GUI for a production install.
        const QStringList candidates = {
            QStringLiteral("target/debug/nrr-service.exe"),
            QStringLiteral("target/release/nrr-service.exe"),
        };
        for (const QString &rel : candidates) {
            servicePath_ = findUpwardFile(applicationDir, rel);
            if (!servicePath_.isEmpty()) { break; }
        }
        if (servicePath_.isEmpty()) {
            // Production install: sibling to the GUI binary.
            const QString sibling =
                QDir(applicationDir).filePath(QStringLiteral("nrr-service.exe"));
            if (QFileInfo::exists(sibling)) {
                servicePath_ = QDir::cleanPath(sibling);
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
        workerThread_.quit();
        workerThread_.wait();
    }

    int status() const { return static_cast<int>(status_); }
    QString statusReason() const { return statusReason_; }
    bool busy() const { return busy_; }
    QString activeOperation() const { return activeOperation_; }

    Q_INVOKABLE void refreshStatus() {
        QString reason;
        const Status next = queryStatus(&reason);
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

    Q_INVOKABLE QString servicePath() const { return servicePath_; }

    /// Directory where the service writes its NDJSON
    /// operational + audit logs. Mirrors
    /// `StorageProfile::ProductionService` topology on the Rust side:
    /// `%ProgramData%\NetRuleRouter\logs`. Returns the parent
    /// `%ProgramData%\NetRuleRouter` if `logs\` doesn't yet exist
    /// (service installed but never started — log dir is created
    /// on first write).
    Q_INVOKABLE QString serviceLogsDirectoryPath() const {
        const QString programData = qEnvironmentVariable("ProgramData");
        if (programData.isEmpty()) { return QString(); }
        const QString logs =
            QDir::cleanPath(programData + QStringLiteral("/NetRuleRouter/logs"));
        if (QFileInfo::exists(logs)) { return logs; }
        const QString parent =
            QDir::cleanPath(programData + QStringLiteral("/NetRuleRouter"));
        if (QFileInfo::exists(parent)) { return parent; }
        return logs;  // return the canonical target even if missing
    }

    Q_INVOKABLE bool isCurrentProcessElevated() const {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            return false;
        }
        TOKEN_ELEVATION elevation{};
        DWORD bytes = 0;
        const BOOL ok = GetTokenInformation(token, TokenElevation,
                                            &elevation, sizeof(elevation), &bytes);
        CloseHandle(token);
        return ok && elevation.TokenIsElevated != 0;
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

    /// Read the current start mode for the toggle.
    /// Runs the UNELEVATED `query-start-mode` verb (SERVICE_QUERY_CONFIG is open
    /// to authenticated users) and returns its slug ("with-windows" /
    /// "on-app-launch"), or an empty string when the service isn't installed or
    /// is unreadable. Synchronous + short — the binary just reads one SCM field.
    Q_INVOKABLE QString queryServiceStartMode() {
        if (servicePath_.isEmpty()) { return QString(); }
        QProcess proc;
#ifdef Q_OS_WIN
        // The service binary is console-subsystem; suppress the conhost flash
        // (CREATE_NO_WINDOW, mirroring the broker's exec).
        proc.setCreateProcessArgumentsModifier(
            [](QProcess::CreateProcessArguments *args) {
                args->flags |= 0x08000000; // CREATE_NO_WINDOW
            });
#endif
        proc.start(servicePath_, QStringList{QStringLiteral("query-start-mode")});
        if (!proc.waitForFinished(3000)) {
            proc.kill();
            return QString();
        }
        if (proc.exitStatus() != QProcess::NormalExit || proc.exitCode() != 0) {
            return QString();
        }
        return QString::fromUtf8(proc.readAllStandardOutput()).trimmed();
    }

signals:
    void statusChanged();
    void busyChanged();
    /// Emitted right before an elevated leg is dispatched to the worker.
    /// Fires once per leg, so a restart raises it twice ("stop" then
    /// "start") and an install raises it for "install" then "start".
    void operationStarted(QString operation);
    void operationCompleted(QString operation, bool success, QString errorMessage);
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
        emit operationCompleted(operation, success, errorMessage);
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

    void dispatch(const QString &operation, const QString &command) {
        if (servicePath_.isEmpty()) {
            setBusy(false, QString());
            emit operationCompleted(operation, false,
                QStringLiteral("Service binary not found"));
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
    void dispatchViaBroker(const QString &operation, const QString &command) {
        const QString corr = bridge_->emitServiceControlRpc(command, servicePath_);
        if (corr.isEmpty()) {
            // No channel — fall back to a direct elevated run.
            QMetaObject::invokeMethod(
                worker_, "runElevated", Qt::QueuedConnection,
                Q_ARG(QString, operation),
                Q_ARG(QString, servicePath_),
                Q_ARG(QString, command));
            return;
        }
        auto conn = std::make_shared<QMetaObject::Connection>();
        *conn = connect(
            bridge_, &NrrNativeBridge::rpcResponse, this,
            [this, conn, corr, operation](
                const QString &cid, bool ok, const QVariant &,
                const QString &errorCode, const QString &errorMessage) {
                if (cid != corr) { return; }
                QObject::disconnect(*conn);
                onBrokerServiceControlResult(operation, ok, errorCode, errorMessage);
            });
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
            emit operationCompleted(operation, false, errorMessage);
            setBusy(false, QString());
            refreshStatus();
            return;
        }
        emit operationCompleted(operation, true, QString());
        // Reaching here means a service-control
        // action succeeded through the broker (non-elevated path), so the
        // broker session is live (UAC was granted). Tell the GUI so its
        // review banner + "revoke" control reflect the elevated session.
        emit brokerSessionEstablished();
        // Auto-start after a successful install (mirrors onWorkerResult);
        // the broker is already up so this second action raises no UAC.
        if (operation == QStringLiteral("install")) {
            refreshStatus();
            dispatch(QStringLiteral("start"), QStringLiteral("start"));
            return;
        }
        setBusy(false, QString());
        refreshStatus();
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
#ifdef Q_OS_WIN
    // Win32 thread id captured at the start of `run()`. Used by
    // `requestStopAndCloseStdin` to call `CancelSynchronousIo` against
    // the reader's own thread handle. DWORD; 0 means "not yet running".
    std::atomic<DWORD> readerThreadId_{0};
#endif
};

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

    QQmlApplicationEngine engine;
    QObject::connect(
        &engine,
        &QQmlApplicationEngine::objectCreationFailed,
        &application,
        [](const QUrl &) { QCoreApplication::exit(1); },
        Qt::QueuedConnection);
    engine.rootContext()->setContextProperty(QStringLiteral("nrrNativeBridge"), &nativeBridge);
    // Service Control Manager bridge. Q_INVOKABLE
    // methods drive the Settings → Service Management panel, the
    // tray status badge, and the first-launch install dialog.
    NrrServiceController serviceController(applicationDir);
    // Let a non-elevated GUI route service
    // control through the session elevation broker (one UAC per session).
    serviceController.setBridge(&nativeBridge);
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

#include "main.moc"
