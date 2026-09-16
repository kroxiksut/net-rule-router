#include "native_bridge.h"

NrrNativeBridge::NrrNativeBridge(const QString &applicationDir, QObject *parent)
    : QObject(parent),
      applicationDir_(applicationDir),
      mainGuiExecutable_(resolveMainGuiExecutable(applicationDir)),
      trayGuiExecutable_(resolveTrayGuiExecutable(applicationDir)),
      guiActivationRequestPath_(guiActivationRequestFilePath()),
      logsDirectory_(resolveLogsDirectory()) {
    watchSystemAppearance();
}

void NrrNativeBridge::triggerTrayAction(const QString &actionId) {
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
    } else if (actionId == QStringLiteral("rules-drift-compare")) {
        // "Open and compare" on the same notice: the window re-measures the
        // three legs and opens the comparison, instead of landing on a rules
        // table that says nothing about the divergence.
        launchMainGuiWithAction(QStringLiteral("rules"), false, false,
                                QStringLiteral("rules-drift-compare"), {});
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

bool NrrNativeBridge::savePreferences(const QString &serializedPayload) {
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

QVariantMap NrrNativeBridge::takePendingGuiRequest() {
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

QString NrrNativeBridge::sha256Hex(const QString &input) {
    const QByteArray bytes = input.toUtf8();
    const QByteArray digest = QCryptographicHash::hash(
        bytes, QCryptographicHash::Sha256);
    return QString::fromLatin1(digest.toHex());
}

QString NrrNativeBridge::decodeBase64Utf8(const QString &b64) {
    const QByteArray raw = QByteArray::fromBase64(b64.toUtf8());
    return QString::fromUtf8(raw);
}

QString NrrNativeBridge::punycodeEncodeHost(const QString &hostname) {
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

QString NrrNativeBridge::punycodeDecodeHost(const QString &hostname) {
    const QString trimmed = hostname.trimmed();
    if (trimmed.isEmpty()) return QString();
    if (!trimmed.contains(QStringLiteral("xn--"), Qt::CaseInsensitive)) {
        return trimmed;
    }
    const QString unicode = QUrl::fromAce(trimmed.toLatin1());
    if (unicode.isEmpty()) return trimmed;
    return unicode;
}

void NrrNativeBridge::copyToClipboard(const QString &text) {
    QClipboard *cb = QGuiApplication::clipboard();
    if (cb != nullptr) {
        cb->setText(text);
    }
}

QVariantMap NrrNativeBridge::trayNoticeScreenGeometry() const {
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

bool NrrNativeBridge::isElevated() {
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

void NrrNativeBridge::openContainingFolder(const QString &path) {
    if (path.isEmpty()) {
        return;
    }
    const QString native = QDir::toNativeSeparators(path);
#ifdef Q_OS_WIN
    QFileInfo info(path);
    if (info.exists()) {
        // `/select,` highlights the file inside its folder.
        QProcess::startDetached(systemExplorerPath(),
                                {QStringLiteral("/select,") + native});
    } else {
        // File gone — fall back to opening the parent directory.
        const QString dir = info.absolutePath();
        if (!dir.isEmpty()) {
            QProcess::startDetached(systemExplorerPath(),
                                    {QDir::toNativeSeparators(dir)});
        }
    }
#else
    QFileInfo info(path);
    QDesktopServices::openUrl(QUrl::fromLocalFile(
        info.exists() ? info.absolutePath() : path));
#endif
}

QString NrrNativeBridge::prepareTrayGrayscaleIcon(const QString &sourceUrl) {
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

QString NrrNativeBridge::prepareTrayStatusIcon(const QString &sourceUrl,
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

bool NrrNativeBridge::ensureTrayRunning() {
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

bool NrrNativeBridge::consumeApplicationShutdownRequest() {
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

bool NrrNativeBridge::requestTrayShutdown() {
    writeTrayShutdownFlag();
    // The tray consumes (deletes) the flag before it exits — latch the
    // intent so its exit is not read as an outside kill.
    trayShutdownExpected_ = true;
    return true;
}

bool NrrNativeBridge::consumeTrayShutdownRequest() {
    const QString path = trayShutdownFlagPath();
    if (QFile::exists(path)) {
        QFile::remove(path);
        return true;
    }
    return false;
}

int NrrNativeBridge::clearGuiLogs() {
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

void NrrNativeBridge::watchSystemAppearance() {
    QStyleHints *hints = QGuiApplication::styleHints();
    if (hints == nullptr) {
        return;
    }
    connect(hints, &QStyleHints::colorSchemeChanged, this,
            [this](Qt::ColorScheme) { emit systemAppearanceChanged(); });
}

void NrrNativeBridge::setMainWindowDarkTitleBar(bool dark) {
    applyDarkTitleBarToWindow(mainWindow_, dark);
}
