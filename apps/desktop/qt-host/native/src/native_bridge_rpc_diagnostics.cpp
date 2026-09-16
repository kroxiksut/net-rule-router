#include "native_bridge.h"

QString NrrNativeBridge::rpcStatusUpdatesSubscribe(const QString &clientId) {
    QJsonObject obj;
    obj.insert(QStringLiteral("client-id"), clientId);
    return emitRpcRequest(QStringLiteral("status.updates.subscribe"), obj);
}

QString NrrNativeBridge::rpcExplainGetByDecisionId(const QString &decisionId,
                                                   const QString &detailLevel) {
    QJsonObject obj;
    obj.insert(QStringLiteral("decision-id"), decisionId);
    if (!detailLevel.isEmpty()) {
        obj.insert(QStringLiteral("detail-level"), detailLevel);
    }
    return emitRpcRequest(QStringLiteral("diagnostics.explain.get"), obj);
}

QString NrrNativeBridge::rpcExplainGetBySample(const QString &hostname,
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

QString NrrNativeBridge::rpcSnapshotInterfacesGet() {
    return emitRpcRequest(QStringLiteral("snapshot.interfaces.get"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcInterfacesRefresh() {
    return emitRpcRequest(QStringLiteral("interfaces.refresh.request"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcLogsClear(bool dryRun, bool includeArchives) {
    QJsonObject obj;
    obj.insert(QStringLiteral("dry-run"), dryRun);
    obj.insert(QStringLiteral("include-archives"), includeArchives);
    return emitRpcRequest(QStringLiteral("logs.clear"), obj);
}

QString NrrNativeBridge::rpcDiagnosticModeSet(bool enabled, double durationMs,
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

QString NrrNativeBridge::rpcCacheClear(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("cache.clear"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcCacheEntriesList(const QString &cursor, int pageSize,
                                            const QString &query) {
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

QString NrrNativeBridge::rpcConnTraceEntriesList(const QString &cursor, int pageSize) {
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

QString NrrNativeBridge::rpcLogsList(const QVariantMap &filter,
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

QString NrrNativeBridge::rpcAuditList(const QVariantMap &filter,
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

QString NrrNativeBridge::rpcDiagnosticsExportArchive(
        bool includeLogs,
        bool includeAuditSummary,
        bool includeTroubleshootingPlaybooks,
        const QString &redactionLevel,
        double logsFromMs) {
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

QString NrrNativeBridge::rpcServiceStabilityConfigGet() {
    return emitRpcRequest(
        QStringLiteral("settings.service-stability.get"), QJsonObject());
}

QString NrrNativeBridge::rpcServiceStabilityConfigSet(const QVariantMap &config,
                                                     const QString &origin) {
    QJsonObject obj;
    obj.insert(QStringLiteral("config"),
               QJsonObject::fromVariantMap(config));
    if (!origin.isEmpty())
        obj.insert(QStringLiteral("origin"), origin);
    return emitRpcRequest(
        QStringLiteral("settings.service-stability.set"), obj);
}

QString NrrNativeBridge::rpcSidecarCommentRead(const QString &type_,
                                              const QString &value,
                                              const QString &route) {
    QJsonObject obj;
    obj.insert(QStringLiteral("type"), type_);
    obj.insert(QStringLiteral("value"), value);
    obj.insert(QStringLiteral("route"), route);
    return emitRpcRequest(QStringLiteral("sidecar.comment.read"), obj);
}

QString NrrNativeBridge::rpcSidecarCommentReadAll() {
    return emitRpcRequest(QStringLiteral("sidecar.comment.read-all"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcSidecarCommentWrite(const QString &type_,
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

QString NrrNativeBridge::rpcSidecarCommentGc(const QVariantList &activeSignatures) {
    QJsonArray arr;
    for (const QVariant &v : activeSignatures) {
        arr.append(QJsonObject::fromVariantMap(v.toMap()));
    }
    QJsonObject obj;
    obj.insert(QStringLiteral("active-signatures"), arr);
    return emitRpcRequest(QStringLiteral("sidecar.comment.gc"), obj);
}

QString NrrNativeBridge::rpcSidecarPassthroughRead(const QString &route) {
    QJsonObject obj;
    obj.insert(QStringLiteral("route"), route);
    return emitRpcRequest(QStringLiteral("sidecar.passthrough.read"), obj);
}

QString NrrNativeBridge::rpcSidecarPassthroughWrite(const QString &route,
                                                   const QVariantMap &sections) {
    QJsonObject obj;
    obj.insert(QStringLiteral("route"), route);
    obj.insert(QStringLiteral("sections"),
               QJsonObject::fromVariantMap(sections));
    return emitRpcRequest(QStringLiteral("sidecar.passthrough.write"), obj);
}

QString NrrNativeBridge::rpcSidecarPendingApplyRead() {
    return emitRpcRequest(QStringLiteral("sidecar.pending-apply.read"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcSidecarPendingApplyWrite(const QString &summaryJson,
                                                    const QString &contentHash) {
    QJsonObject obj;
    obj.insert(QStringLiteral("summary-json"), summaryJson);
    obj.insert(QStringLiteral("content-hash"), contentHash);
    return emitRpcRequest(QStringLiteral("sidecar.pending-apply.write"), obj);
}

QString NrrNativeBridge::rpcSidecarPendingApplyClear() {
    return emitRpcRequest(QStringLiteral("sidecar.pending-apply.clear"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcSidecarExternalIpReadAll() {
    return emitRpcRequest(QStringLiteral("sidecar.external-ip.read-all"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcSidecarExternalIpWriteAll(const QVariantList &entries) {
    QJsonArray arr;
    for (const QVariant &v : entries) {
        arr.append(QJsonObject::fromVariantMap(v.toMap()));
    }
    QJsonObject obj;
    obj.insert(QStringLiteral("entries"), arr);
    return emitRpcRequest(QStringLiteral("sidecar.external-ip.write-all"), obj);
}

QString NrrNativeBridge::rpcSidecarVacuum(bool force) {
    QJsonObject obj;
    obj.insert(QStringLiteral("force"), force);
    return emitRpcRequest(QStringLiteral("sidecar.vacuum"), obj);
}

QString NrrNativeBridge::rpcSidecarReset() {
    return emitRpcRequest(QStringLiteral("sidecar.reset"), QJsonObject());
}

QString NrrNativeBridge::rpcPresetParse(const QString &text) {
    QJsonObject obj;
    obj.insert(QStringLiteral("text"), text);
    return emitRpcRequest(QStringLiteral("preset.parse"), obj);
}
