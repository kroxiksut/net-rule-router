//! One place that says which handler answers which operation.
//!
//! Split out of `ipc_handlers`; the code is unchanged.

use super::*;

/// Register handlers for every operation in [`IpcOperationName::ALL`].
/// Operations whose real implementation has not yet landed resolve to
/// [`UnimplementedHandler`] (which surfaces `RecoveryRequired` to the
/// client). Individual entries are swapped for real
/// implementations without changing this entrypoint's signature.
pub fn register_production_handlers(registry: &mut IpcHandlerRegistry, deps: Arc<IpcHandlerDeps>) {
    for op in IpcOperationName::ALL {
        match op {
            IpcOperationName::ContractNegotiate => {
                registry.register(op, ContractNegotiateHandler::new());
            }
            IpcOperationName::ServiceHealthGet => {
                let mut handler =
                    ServiceHealthHandler::new(deps.health.clone(), deps.policy.clone());
                if let Some(probe) = deps.fake_ip_datapath_probe.as_ref() {
                    handler = handler.with_fake_ip_datapath_probe(Arc::clone(probe));
                }
                registry.register(op, handler);
            }
            IpcOperationName::SnapshotInterfacesGet => {
                // Chain the Fail-Closed probe when
                // wired so the GUI banner reflects per-SID state.
                // Without a probe (test deps / degraded boot) the
                // handler omits the enforcement banner.
                let mut handler = SnapshotInterfacesHandler::new(deps.adapters.clone());
                if let Some(probe) = deps.fail_closed_probe.clone() {
                    handler = handler.with_fail_closed_probe(probe);
                }
                registry.register(op, handler);
            }
            IpcOperationName::SnapshotDiagnosticsGet => {
                registry.register(
                    op,
                    SnapshotDiagnosticsHandler::new(deps.diagnostics.clone()),
                );
            }
            IpcOperationName::SnapshotInitialGet => {
                let mut handler = SnapshotInitialHandler::new(
                    deps.health.clone(),
                    deps.policy.clone(),
                    deps.adapters.clone(),
                    deps.diagnostics.clone(),
                    deps.route_policy.clone(),
                    deps.apply_failure_policy.clone(),
                    deps.routing_pause.clone(),
                    deps.autostart.clone(),
                    deps.retention.clone(),
                    deps.app_enforcement.clone(),
                    deps.shared_ip_exemptions.clone(),
                    deps.block_all_posture.clone(),
                );
                if let Some(probe) = deps.fake_ip_datapath_probe.as_ref() {
                    handler = handler.with_fake_ip_datapath_probe(Arc::clone(probe));
                }
                registry.register(op, handler);
            }
            IpcOperationName::MutationSubmit => {
                // Wire the tamper gate when the
                // alerts repo is available, so a non-alert mutation is
                // refused while an unacknowledged DB tamper / key-reset
                // alert is active.
                let mut handler = MutationSubmitHandler::new(
                    deps.mutation_executor.clone(),
                    deps.mutation_tokens.clone(),
                    deps.operations.clone(),
                );
                if let Some(repo) = deps.alerts_repo.clone() {
                    handler = handler.with_alerts_repo(repo);
                }
                if let Some(reads) = deps.other_principals_hold_revisions.clone() {
                    handler = handler.with_other_principals_reader(reads);
                }
                // Administrative rules lock — refuse a non-elevated caller's
                // rule change with a typed wire code the client renders as a
                // read-only rules section.
                if let Some(stability) = deps.service_stability_provider.clone() {
                    handler = handler.with_stability_provider(stability);
                }
                registry.register(op, handler);
            }
            IpcOperationName::OperationStatusGet => {
                registry.register(op, OperationStatusHandler::new(deps.operations.clone()));
            }
            IpcOperationName::RollbackRequest => {
                let mut handler =
                    RollbackHandler::new(deps.mutation_executor.clone(), deps.operations.clone());
                // Re-activating an older revision is a rule change too.
                if let Some(stability) = deps.service_stability_provider.clone() {
                    handler = handler.with_stability_provider(stability);
                }
                registry.register(op, handler);
            }
            IpcOperationName::InterfacesRefreshRequest => {
                registry.register(op, InterfacesRefreshHandler::new(deps.adapters.clone()));
            }
            IpcOperationName::ProductImpactDisableTemporary => {
                registry.register(
                    op,
                    ProductImpactDisableTemporaryHandler::new(
                        deps.mutation_executor.clone(),
                        deps.mutation_tokens.clone(),
                        deps.operations.clone(),
                    ),
                );
            }
            IpcOperationName::StatusUpdatesPoll => {
                registry.register(op, StatusUpdatesPollHandler::new());
            }
            IpcOperationName::StatusUpdatesSubscribe => {
                registry.register(
                    op,
                    StatusUpdatesSubscribeHandler::new(deps.event_bus.clone()),
                );
            }
            IpcOperationName::LogsList => {
                registry.register(op, LogsListHandler::new(deps.diagnostics.clone()));
            }
            IpcOperationName::AuditList => {
                registry.register(op, AuditListHandler::new(deps.diagnostics.clone()));
            }
            IpcOperationName::SecurityAlertsList => {
                registry.register(op, SecurityAlertsHandler::new(deps.alerts_repo.clone()));
            }
            IpcOperationName::RulesList => {
                registry.register(op, RulesListHandler::new(deps.rules.clone()));
            }
            IpcOperationName::RoutePolicyUpdate => {
                registry.register(
                    op,
                    RoutePolicyUpdateHandler::new(
                        deps.route_policy_writer.clone(),
                        deps.route_policy_apply_trigger.clone(),
                    ),
                );
            }
            IpcOperationName::RouteLinkProviderSet => {
                // Real handler only when the state-DB-backed
                // writer is wired; a degraded boot keeps the stub.
                if let Some(writer) = deps.link_provider_writer.clone() {
                    registry.register(
                        op,
                        RouteLinkProviderSetHandler::new(
                            writer,
                            deps.route_policy_apply_trigger.clone(),
                        ),
                    );
                } else {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            }
            IpcOperationName::DohResolversGet => {
                if let Some(store) = deps.doh_resolver_store.clone() {
                    registry.register(op, DohResolversGetHandler::new(store));
                } else {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            }
            IpcOperationName::DohResolversSet => {
                if let Some(store) = deps.doh_resolver_store.clone() {
                    registry.register(
                        op,
                        DohResolversSetHandler::new(store, deps.route_policy_apply_trigger.clone()),
                    );
                } else {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            }
            IpcOperationName::SeedFromBrowserHistory => {
                if let Some(seeder) = deps.browser_history_seeder.clone() {
                    registry.register(op, SeedFromBrowserHistoryHandler::new(seeder));
                } else {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            }
            IpcOperationName::MigrationStatusGet => {
                registry.register(
                    op,
                    MigrationStatusGetHandler::new(deps.migration_status.clone()),
                );
            }
            IpcOperationName::MigrationMarkComplete => {
                registry.register(
                    op,
                    MigrationMarkCompleteHandler::new(deps.migration_completion.clone()),
                );
            }
            // Settings ops.
            IpcOperationName::RetentionSettingsGet => {
                registry.register(op, RetentionSettingsGetHandler::new(deps.retention.clone()));
            }
            IpcOperationName::RetentionSettingsSet => {
                registry.register(
                    op,
                    RetentionSettingsSetHandler::new(
                        deps.retention_writer.clone(),
                        deps.retention.clone(),
                    ),
                );
            }
            // Log/audit retention config.
            IpcOperationName::LogRetentionConfigGet => {
                registry.register(
                    op,
                    LogRetentionConfigGetHandler::new(deps.log_retention.clone()),
                );
            }
            IpcOperationName::LogRetentionConfigSet => {
                registry.register(
                    op,
                    LogRetentionConfigSetHandler::new(
                        deps.log_retention_writer.clone(),
                        deps.log_retention.clone(),
                    ),
                );
            }
            IpcOperationName::ApplyFailurePolicyGet => {
                registry.register(
                    op,
                    ApplyFailurePolicyGetHandler::new(deps.apply_failure_policy.clone()),
                );
            }
            IpcOperationName::ApplyFailurePolicySet => {
                registry.register(
                    op,
                    ApplyFailurePolicySetHandler::new(
                        deps.apply_failure_policy_writer.clone(),
                        deps.apply_failure_policy.clone(),
                    ),
                );
            }
            IpcOperationName::StorageUsageGet => {
                registry.register(op, StorageUsageGetHandler::new(deps.storage_usage.clone()));
            }
            IpcOperationName::RoutingPauseGet => {
                registry.register(op, RoutingPauseGetHandler::new(deps.routing_pause.clone()));
            }
            IpcOperationName::RoutingPauseToggle => {
                registry.register(
                    op,
                    RoutingPauseToggleHandler::new(deps.routing_pause_writer.clone()),
                );
            }
            IpcOperationName::AutostartGet => {
                registry.register(op, AutostartGetHandler::new(deps.autostart.clone()));
            }
            IpcOperationName::AutostartToggle => {
                registry.register(
                    op,
                    AutostartToggleHandler::new(deps.autostart_writer.clone()),
                );
            }
            // Each gates on its dep being wired; missing dep falls back to
            // the fallback stub so the catalog-coverage test still sees
            // `RecoveryRequired` when the runtime hasn't fully wired the op
            // (degraded boot path).
            IpcOperationName::ExplainGet => {
                // The kill-switch enforcement verdict reuses
                // the conn-trace expectation deps (fqdn cache + active SID)
                // plus the per-SID policy reader; absent expectation deps →
                // rule verdict only (compact.enforcement stays empty).
                let handler =
                    diagnostics_handlers::ExplainGetHandler::new(deps.diagnostics.clone());
                let handler = match deps.conn_trace_expectation.clone() {
                    Some((_rules, fqdn, active_sid)) => handler.with_enforcement_verdict(
                        deps.route_policy.clone(),
                        fqdn,
                        active_sid,
                    ),
                    None => handler,
                };
                // The synthetic hostname probe carries the virtual
                // address the resolver answers with when fake-IP is wired.
                let handler = match deps.fake_ip_bindings.clone() {
                    Some(view) => handler.with_fake_ip_bindings(view),
                    None => handler,
                };
                registry.register(op, handler);
            }
            IpcOperationName::DiagnosticsExportArchive => {
                match (deps.archives_dir.clone(), deps.app_version.clone()) {
                    (Some(dir), Some(ver)) => {
                        registry.register(
                            op,
                            diagnostics_handlers::DiagnosticsExportArchiveHandler::new(
                                deps.diagnostics.clone(),
                                dir,
                                ver,
                                deps.system_info.clone(),
                                deps.adapters.clone(),
                                deps.route_policy.clone(),
                                deps.state_schema_version,
                                deps.file_handoff.clone().unwrap_or_else(|| {
                                    Arc::new(nrr_platform_api::file_handoff::NoopFileHandoff)
                                }),
                            ),
                        );
                    }
                    _ => {
                        registry.register(op, UnimplementedHandler::new(op));
                    }
                }
            }
            IpcOperationName::ServiceStabilityConfigGet => {
                match deps.service_stability_provider.clone() {
                    Some(provider) => {
                        registry.register(
                            op,
                            service_stability_handlers::ServiceStabilityConfigGetHandler::new(
                                provider,
                            ),
                        );
                    }
                    None => {
                        registry.register(op, UnimplementedHandler::new(op));
                    }
                }
            }
            IpcOperationName::ServiceStabilityConfigSet => {
                match deps.service_stability_writer.clone() {
                    Some(writer) => {
                        let mut handler =
                            service_stability_handlers::ServiceStabilityConfigSetHandler::new(
                                writer,
                            );
                        // The reader lets the handler tell a real change of the
                        // administrative rules lock from a client echoing the
                        // stored value back on an unrelated save.
                        if let Some(provider) = deps.service_stability_provider.clone() {
                            handler = handler.with_provider(provider);
                        }
                        registry.register(op, handler);
                    }
                    None => {
                        registry.register(op, UnimplementedHandler::new(op));
                    }
                }
            }
            // Real LogsClear handler. The facade
            // is always present (mock or production); no dep gate.
            IpcOperationName::LogsClear => {
                registry.register(
                    op,
                    diagnostics_handlers::LogsClearHandler::new(deps.diagnostics.clone()),
                );
            }
            // DiagnosticModeSet: the facade is always present, so register
            // the real handler unconditionally (like LogsClear).
            IpcOperationName::DiagnosticModeSet => {
                registry.register(
                    op,
                    diagnostics_handlers::DiagnosticModeSetHandler::new(deps.diagnostics.clone()),
                );
            }
            // CacheClear handler. The FQDN/IP cache DB may
            // be absent or corrupt, so register the real handler only when
            // the repository is wired; otherwise keep the Unimplemented stub
            // so the catalog-coverage invariant still holds.
            IpcOperationName::CacheClear => match deps.cache_repository.clone() {
                Some(cache) => {
                    // Attach the OS-DNS-flush port when wired so the
                    // GUI's "clear OS DNS cache" button works; without it the
                    // handler still clears the app SQLite cache.
                    let mut handler = diagnostics_handlers::CacheClearHandler::new(cache);
                    if let Some(port) = deps.dns_cache_control.clone() {
                        handler = handler.with_dns_cache_control(port);
                    }
                    registry.register(op, handler);
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            // CacheEntriesList (read-only cache viewer). Gated
            // on the same cache repository as CacheClear; the diagnostics
            // facade (always present) supplies the redaction tier. Falls
            // back to the Unimplemented stub when the cache DB is absent.
            IpcOperationName::CacheEntriesList => match deps.cache_repository.clone() {
                Some(cache) => {
                    // When the expectation inputs are wired (same
                    // tuple the conn-trace handler uses), rows carry
                    // `expected_route` (the cache viewer's "Route" column).
                    let handler = diagnostics_handlers::CacheEntriesListHandler::new(cache);
                    let handler = match deps.conn_trace_expectation.clone() {
                        Some((rules, fqdn, active_sid)) => {
                            handler.with_route_expectation(rules, fqdn, active_sid)
                        }
                        None => handler,
                    };
                    // Each row carries the virtual address next to the
                    // real one when fake-IP is wired.
                    let handler = match deps.fake_ip_bindings.clone() {
                        Some(view) => handler.with_fake_ip_bindings(view),
                        None => handler,
                    };
                    registry.register(op, handler);
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            // ConnTraceEntriesList (read-only connection-trace viewer).
            // Gated on the connection-trace ring (always wired in production).
            // The local own-machine viewer is never redacted, so it does not
            // need the diagnostics facade. Falls back to the
            // Unimplemented stub when the ring is absent (test fakes).
            IpcOperationName::ConnTraceEntriesList => match deps.conn_trace_ring.clone() {
                Some(ring) => {
                    // When the expectation inputs are wired, rows
                    // carry `expected_route` (leak flagging in the GUI trace).
                    let handler = diagnostics_handlers::ConnTraceEntriesListHandler::new(ring);
                    // "Show connection trace in the GUI" gates the ANSWER, not
                    // the observer — the same stream feeds app-routing and the
                    // learners, which the switch has no business stopping.
                    let handler = match deps.service_stability_provider.clone() {
                        Some(settings) => handler.with_gui_stream_gate(settings),
                        None => handler,
                    };
                    let handler = match deps.conn_trace_expectation.clone() {
                        Some((rules, fqdn, active_sid)) => {
                            handler.with_route_expectation(rules, fqdn, active_sid)
                        }
                        None => handler,
                    };
                    registry.register(op, handler);
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            // Attribution + integrity of shipped
            // third-party components. Always a real handler: without an
            // inspector it reports the attribution-only assets and no
            // binaries, which is the correct answer where none are shipped.
            IpcOperationName::ThirdPartyComponentsList => {
                let integrity = deps.third_party_integrity.clone().unwrap_or_else(|| {
                    Arc::new(nrr_platform_api::third_party::NoopThirdPartyIntegrity)
                });
                registry.register(
                    op,
                    third_party_handlers::ThirdPartyComponentsListHandler::new(integrity),
                );
            }
            // PresetExportGet handler. When the
            // `PresetExportSource` is wired, register the real
            // handler; otherwise keep the Unimplemented stub so the
            // catalog-coverage invariant holds in degraded boot paths.
            IpcOperationName::PresetExportGet => match deps.preset_export_source.clone() {
                Some(source) => {
                    registry.register(op, preset_handlers::PresetExportGetHandler::new(source));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            // SettingsExportFull handler. Registered
            // only when BOTH the source and the clock are wired (the
            // handler needs `now_secs` for `exported_at`); otherwise
            // falls back to the Unimplemented stub.
            IpcOperationName::SettingsExportFull => {
                match (
                    deps.settings_export_source.clone(),
                    deps.settings_export_clock.clone(),
                ) {
                    (Some(source), Some(clock)) => {
                        registry.register(
                            op,
                            preset_handlers::SettingsExportFullHandler::new(source, clock),
                        );
                    }
                    _ => {
                        registry.register(op, UnimplementedHandler::new(op));
                    }
                }
            }
            // RulesMergePreview handler. Gated on the merge
            // source (needs the state DB); falls back to the Unimplemented
            // stub in degraded boot so the catalog-coverage invariant holds.
            IpcOperationName::RulesMergePreview => match deps.merge_preview_source.clone() {
                Some(source) => {
                    registry.register(op, merge_preview::RulesMergePreviewHandler::new(source));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            // Gated on the sampler-backed deps.
            IpcOperationName::TrafficStatsGet => match deps.traffic_stats.clone() {
                Some(provider) => {
                    registry.register(op, TrafficStatsGetHandler::new(provider));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::TrafficStatsSet => match deps.traffic_stats_writer.clone() {
                Some(writer) => {
                    registry.register(op, TrafficStatsSetHandler::new(writer));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::TrafficHistoryMergeSet => match deps.traffic_stats_writer.clone() {
                Some(writer) => {
                    registry.register(op, TrafficHistoryMergeSetHandler::new(writer));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::TrafficStatsClear => match deps.traffic_stats_writer.clone() {
                Some(writer) => {
                    registry.register(op, TrafficStatsClearHandler::new(writer));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::AutoRuleCandidatesProbe => match deps.auto_rule_probe.clone() {
                Some(runner) => {
                    registry.register(op, AutoRuleCandidatesProbeHandler::new(runner));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::RefusingAnchorSet => match deps.refusing_anchors.clone() {
                Some(writer) => {
                    registry.register(op, RefusingAnchorSetHandler::new(writer));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::LocalNetworksGet => match deps.local_networks.clone() {
                Some(provider) => {
                    registry.register(op, LocalNetworksGetHandler::new(provider));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::LocalNetworksSet => match deps.local_networks.clone() {
                Some(provider) => {
                    registry.register(op, LocalNetworksSetHandler::new(provider));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            // Companion-domain suggestions — gated on the engine,
            // which is only wired when the DNS-observation path exists.
            IpcOperationName::AutoRuleCandidatesList => match deps.auto_rules.clone() {
                Some(engine) => {
                    registry.register(op, AutoRuleCandidatesListHandler::new(engine));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::AutoRuleCandidatesAccept => match deps.auto_rules.clone() {
                Some(engine) => {
                    registry.register(op, AutoRuleCandidatesAcceptHandler::new(engine));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::AutoRuleCandidatesDismiss => match deps.auto_rules.clone() {
                Some(engine) => {
                    registry.register(op, AutoRuleCandidatesDismissHandler::new(engine));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::AutoRuleCandidatesForget => match deps.auto_rules.clone() {
                Some(engine) => {
                    registry.register(op, AutoRuleCandidatesForgetHandler::new(engine));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::AutoRuleDismissedList => match deps.auto_rules.clone() {
                Some(engine) => {
                    registry.register(op, AutoRuleDismissedListHandler::new(engine));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::AutoRuleDismissedRestore => match deps.auto_rules.clone() {
                Some(engine) => {
                    registry.register(op, AutoRuleDismissedRestoreHandler::new(engine));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            // The backlog a surface drains when it comes up. Gated on its own
            // store: mutes can work without it and it without them.
            IpcOperationName::BlockNoticeJournalList => match deps.block_notice_journal.clone() {
                Some(store) => {
                    registry.register(op, BlockNoticeJournalListHandler::new(store));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::BlockNoticeJournalAck => match deps.block_notice_journal.clone() {
                Some(store) => {
                    registry.register(op, BlockNoticeJournalAckHandler::new(store));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            // Block-notice mutes — gated on the durable store; the
            // live-ledger owner is wired alongside it by
            // `with_block_notice_mutes`, never independently.
            IpcOperationName::BlockNoticeMutesList => match deps.block_notice_mutes.clone() {
                Some(store) => {
                    registry.register(op, BlockNoticeMutesListHandler::new(store));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::BlockNoticeMutesSet => {
                match (
                    deps.block_notice_mutes.clone(),
                    deps.block_notice_center.clone(),
                ) {
                    (Some(store), Some(center)) => {
                        registry.register(op, BlockNoticeMutesSetHandler::new(store, center));
                    }
                    _ => {
                        registry.register(op, UnimplementedHandler::new(op));
                    }
                }
            }
            IpcOperationName::BlockNoticeMutesRemove => {
                match (
                    deps.block_notice_mutes.clone(),
                    deps.block_notice_center.clone(),
                ) {
                    (Some(store), Some(center)) => {
                        registry.register(op, BlockNoticeMutesRemoveHandler::new(store, center));
                    }
                    _ => {
                        registry.register(op, UnimplementedHandler::new(op));
                    }
                }
            }
            IpcOperationName::BlockNoticeMutesClear => {
                match (
                    deps.block_notice_mutes.clone(),
                    deps.block_notice_center.clone(),
                ) {
                    (Some(store), Some(center)) => {
                        registry.register(op, BlockNoticeMutesClearHandler::new(store, center));
                    }
                    _ => {
                        registry.register(op, UnimplementedHandler::new(op));
                    }
                }
            }
            // Turns a block notice into a rule through the SAME author the
            // companion-domain `accept` path uses.
            IpcOperationName::BlockNoticeRouteToSecondary => {
                match deps.block_notice_author.clone() {
                    Some(author) => {
                        let mut handler = BlockNoticeRouteToSecondaryHandler::new(author);
                        // Without the centre the rule lands but the notice that
                        // asked for it keeps standing.
                        if let Some(center) = deps.block_notice_center.clone() {
                            handler = handler.with_center(center);
                        }
                        registry.register(op, handler);
                    }
                    None => {
                        registry.register(op, UnimplementedHandler::new(op));
                    }
                }
            }
            IpcOperationName::PrincipalDataPurge => match deps.principal_data_purger.clone() {
                Some(purger) => {
                    registry.register(op, PrincipalDataPurgeHandler::new(purger));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::PrincipalDataCount => match deps.principal_data_purger.clone() {
                Some(purger) => {
                    registry.register(op, PrincipalDataCountHandler::new(purger));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
        }
    }
}
