#include "native_bridge.h"

QString NrrNativeBridge::readFileBytes(const QString &path) {
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

QVariantMap NrrNativeBridge::statFile(const QString &path) {
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

QString NrrNativeBridge::rpcCanonicalRulesHash(const QString &rulesJson) {
    QJsonObject obj;
    obj.insert(QStringLiteral("rules-json"), rulesJson);
    return emitRpcRequest(QStringLiteral("local.canonical-rules-hash"),
                          obj);
}

QString NrrNativeBridge::rpcRulesOverlaps(const QString &rulesJson) {
    QJsonObject obj;
    obj.insert(QStringLiteral("rules-json"), rulesJson);
    return emitRpcRequest(QStringLiteral("local.rules-overlaps"), obj);
}

QString NrrNativeBridge::rpcVpnDiscover() {
    return emitRpcRequest(QStringLiteral("local.vpn.discover"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcAppGroupsDiscover() {
    return emitRpcRequest(QStringLiteral("local.app-groups.discover"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcVmInventoryList() {
    return emitRpcRequest(QStringLiteral("local.vm-inventory.list"), QJsonObject());
}

QString NrrNativeBridge::rpcSeedFromBrowserHistory() {
    return emitRpcRequest(QStringLiteral("diagnostics.seed-from-browser-history"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcSystemTheme() {
    return emitRpcRequest(QStringLiteral("local.system-theme"), QJsonObject());
}

QString NrrNativeBridge::rpcServiceInfo() {
    return emitRpcRequest(QStringLiteral("local.service-info"),
                          QJsonObject());
}

QString NrrNativeBridge::detectOsLocale() {
    return QLocale::system().name().toLower();
}

QString NrrNativeBridge::listCountryPresets(const QString &countryCode) {
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

QString NrrNativeBridge::listAllPresets(const QString &rootOverride) {
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

QString NrrNativeBridge::resolvePresetPath(const QString &relativePath,
                                          const QString &rootOverride) {
    if (relativePath.isEmpty()) {
        return QString();
    }
    // The caller names a set inside a preset root; a relative path that
    // climbs out of it names something else entirely, and this result is
    // handed straight to a file read.
    if (relativePath.contains(QStringLiteral(".."))
        || QDir::isAbsolutePath(relativePath)) {
        qWarning() << "resolvePresetPath: refusing to leave the preset root:"
                   << relativePath;
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

QString NrrNativeBridge::defaultLocalAppDataPath(const QString &filename) {
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

QString NrrNativeBridge::findPresetsRoot() const {
    return findBundledFile(applicationDir_, QStringLiteral("presets"));
}

QString NrrNativeBridge::listUserPresets(const QDir &root) const {
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

QString NrrNativeBridge::findConfigsPresetsRoot() const {
    return findBundledFile(applicationDir_, QStringLiteral("configs/presets"));
}

QString NrrNativeBridge::runtimeDiagnosticsPath(const QString &filename) {
    const QString name = filename.trimmed();
    if (name.isEmpty() || name.contains(QLatin1Char('/'))
            || name.contains(QLatin1Char('\\'))) {
        return QString();
    }
    QDir dir(appRuntimeDirectoryPath());
    if (!dir.exists(QStringLiteral("diagnostics"))
            && !dir.mkpath(QStringLiteral("diagnostics"))) {
        qWarning() << "runtimeDiagnosticsPath: mkpath failed under"
                   << dir.absolutePath();
        return QString();
    }
    return dir.filePath(QStringLiteral("diagnostics/") + name);
}

bool NrrNativeBridge::writeTextFile(const QString &path, const QString &text) {
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

QString NrrNativeBridge::bundledPresetsRoot() {
    return findPresetsRoot();
}

bool NrrNativeBridge::isPathUnderBundledPresets(const QString &path) {
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

QString NrrNativeBridge::createPresetSetDir(const QString &rootDir,
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

bool NrrNativeBridge::writeFileBytes(const QString &path,
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
