#include "native_bridge.h"

QString NrrNativeBridge::rpcServiceHealthGet() {
    return emitRpcRequest(QStringLiteral("service.health.get"), QJsonObject());
}

QString NrrNativeBridge::rpcRoutePolicyUpdate(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("route.policy.update"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcRouteLinkProviderSet(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("route.link-provider.set"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcLocalNetworksGet() {
    return emitRpcRequest(QStringLiteral("settings.local-networks.get"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcLocalNetworksSet(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("settings.local-networks.set"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcAutoRuleCandidatesList() {
    return emitRpcRequest(QStringLiteral("autorules.candidates.list"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcAutoRuleCandidatesAccept(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("autorules.candidates.accept"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcAutoRuleCandidatesDismiss(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("autorules.candidates.dismiss"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcRefusingAnchorSet(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("autorules.refusing-anchor.set"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcAutoRuleCandidatesProbe(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("autorules.candidates.probe"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcAutoRuleCandidatesForget(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("autorules.candidates.forget"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcAutoRuleDismissedList() {
    return emitRpcRequest(QStringLiteral("autorules.dismissed.list"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcAutoRuleDismissedRestore(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("autorules.dismissed.restore"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcBlockNoticeMutesList() {
    return emitRpcRequest(QStringLiteral("block-notices.mutes.list"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcBlockNoticeMutesSet(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("block-notices.mutes.set"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcBlockNoticeMutesRemove(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("block-notices.mutes.remove"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcBlockNoticeMutesClear() {
    return emitRpcRequest(QStringLiteral("block-notices.mutes.clear"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcBlockNoticeJournalList() {
    return emitRpcRequest(QStringLiteral("block-notices.journal.list"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcBlockNoticeJournalAck(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("block-notices.journal.ack"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcBlockNoticeRouteToSecondary(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("block-notices.route-to-secondary"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcPrincipalDataPurge(bool includeRulesHistory,
                                              bool allPrincipals) {
    QJsonObject payload;
    payload.insert(QStringLiteral("include-rules-history"), includeRulesHistory);
    payload.insert(QStringLiteral("all-principals"), allPrincipals);
    return emitRpcRequest(QStringLiteral("principal-data.purge"), payload);
}

QString NrrNativeBridge::rpcPrincipalDataCount() {
    return emitRpcRequest(QStringLiteral("principal-data.count"), QJsonObject());
}

QString NrrNativeBridge::rpcDohResolversGet() {
    return emitRpcRequest(QStringLiteral("doh.resolvers.get"), QJsonObject());
}

QString NrrNativeBridge::rpcTrafficStatsGet(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("traffic-stats.get"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcTrafficStatsSet(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("traffic-stats.set"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcTrafficStatsClear() {
    return emitRpcRequest(QStringLiteral("traffic-stats.clear"), QJsonObject());
}

QString NrrNativeBridge::rpcTrafficHistoryMergeSet(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("traffic-stats.history-merge.set"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcDohResolversSet(const QString &resolversJson) {
    QJsonParseError parseError{};
    const QJsonDocument doc =
        QJsonDocument::fromJson(resolversJson.toUtf8(), &parseError);
    QJsonObject obj;
    if (parseError.error == QJsonParseError::NoError && doc.isObject()) {
        obj = doc.object();
    }
    return emitRpcRequest(QStringLiteral("doh.resolvers.set"), obj);
}

QString NrrNativeBridge::rpcBrokerRevoke() {
    return emitRpcRequest(QStringLiteral("local.broker-revoke"), QJsonObject());
}

QString NrrNativeBridge::rpcBrokerStatus(const QJsonObject &payload) {
    return emitRpcRequest(QStringLiteral("local.broker-status"), payload);
}

QString NrrNativeBridge::emitServiceControlRpc(const QString &action,
                                  const QString &serviceExePath) {
    QJsonObject obj;
    obj.insert(QStringLiteral("action"), action);
    obj.insert(QStringLiteral("service-exe-path"), serviceExePath);
    return emitRpcRequest(QStringLiteral("local.service-control"), obj);
}

QString NrrNativeBridge::rpcSnapshotInitialGet() {
    return emitRpcRequest(QStringLiteral("snapshot.initial.get"), QJsonObject());
}

QString NrrNativeBridge::rpcRulesList() {
    return emitRpcRequest(QStringLiteral("rules.list"), QJsonObject());
}

QString NrrNativeBridge::rpcRetentionSettingsGet() {
    return emitRpcRequest(QStringLiteral("settings.retention.get"), QJsonObject());
}

QString NrrNativeBridge::rpcRetentionSettingsSet(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("settings.retention.set"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcLogRetentionConfigGet() {
    return emitRpcRequest(QStringLiteral("settings.log-retention.get"), QJsonObject());
}

QString NrrNativeBridge::rpcLogRetentionConfigSet(const QVariantMap &payload) {
    return emitRpcRequest(QStringLiteral("settings.log-retention.set"),
                          QJsonObject::fromVariantMap(payload));
}

QString NrrNativeBridge::rpcApplyFailurePolicyGet() {
    return emitRpcRequest(QStringLiteral("settings.apply-failure-policy.get"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcApplyFailurePolicySet(const QString &policy) {
    QJsonObject obj;
    obj.insert(QStringLiteral("policy"), policy);
    return emitRpcRequest(QStringLiteral("settings.apply-failure-policy.set"), obj);
}

QString NrrNativeBridge::rpcStorageUsageGet() {
    return emitRpcRequest(QStringLiteral("storage.usage.get"), QJsonObject());
}

QString NrrNativeBridge::rpcThirdPartyComponentsList() {
    return emitRpcRequest(QStringLiteral("third-party.components.list"), QJsonObject());
}

QString NrrNativeBridge::rpcRoutingPauseGet() {
    return emitRpcRequest(QStringLiteral("routing.pause.get"), QJsonObject());
}

QString NrrNativeBridge::rpcRoutingPauseToggle(bool paused, const QString &reason) {
    QJsonObject obj;
    obj.insert(QStringLiteral("paused"), paused);
    if (!reason.isEmpty()) {
        obj.insert(QStringLiteral("reason"), reason);
    }
    return emitRpcRequest(QStringLiteral("routing.pause.toggle"), obj);
}

QString NrrNativeBridge::rpcAutostartGet() {
    return emitRpcRequest(QStringLiteral("autostart.get"), QJsonObject());
}

QString NrrNativeBridge::rpcAutostartToggle(bool enabled) {
    QJsonObject obj;
    obj.insert(QStringLiteral("enabled"), enabled);
    return emitRpcRequest(QStringLiteral("autostart.toggle"), obj);
}

QString NrrNativeBridge::rpcConsolePathState() {
    return emitRpcRequest(QStringLiteral("local.console-path.state"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcConsolePathRegister() {
    return emitRpcRequest(QStringLiteral("local.console-path.register"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcConsolePathUnregister() {
    return emitRpcRequest(QStringLiteral("local.console-path.unregister"),
                          QJsonObject());
}

QString NrrNativeBridge::rpcMutationSubmit(const QString &mutationKind,
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

QString NrrNativeBridge::rpcRollbackRequest(const QString &targetRevisionId,
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

QString NrrNativeBridge::rpcProductImpactDisable(const QString &reason,
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

QString NrrNativeBridge::rpcPresetExport(const QString &route,
                                        bool includeMetadata) {
    QJsonObject obj;
    obj.insert(QStringLiteral("route"), route);
    obj.insert(QStringLiteral("include-metadata"), includeMetadata);
    return emitRpcRequest(QStringLiteral("preset.export.get"), obj);
}

QString NrrNativeBridge::rpcSettingsExportFull(
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
