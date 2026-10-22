# Local validation, 2026-10-22

Release status: **NOT VERIFIED END TO END**. This records observed results and
does not certify production readiness or all eleven MCP execution paths.

| Check | Observed result |
| --- | --- |
| `poetry run pytest --no-cov -q` | 6687 passed, 67 failed, 483 skipped; 505.93 seconds |
| `go test ./...` in `mcp-servers/go` | Passed |
| `npm --prefix ui run typecheck` | Passed |
| `npm --prefix ui run build` | Passed |
| `node --test ui/tests/*.test.mjs` | 320 passed, zero failures |
| Real installed Checkov through local Cloud ASGI MCP | Passed; static Terraform findings only |
| Focused eleven-provider bootstrap/recovery and Cloud bearer HTTP rerun | 61 passed; fixtures prove transport and authorization boundaries only |
| `mcp_validator.py --public-intel-smoke` | Threat Intel public lookup verified; other ten default endpoints unreachable |

The Python run includes default skip conditions. It does not exercise all
opt-in database and provider qualifications. Its failures include startup
inventory tests that parse the old registration layout, obsolete Cloud stub
expectations, Browser signed-source setup, report provenance/release fixtures,
subscription route assumptions, migration-head assumptions, and SSE framing.
The startup inventory assertion in `test_mcp_eleven_execution_truth_20261021.py`
was updated after that full run to inspect the current configuration helper.
Individual reruns must not be represented as a second full-suite pass.

The exact failure identifiers and tracebacks are retained locally in
`.runtime/pytest-full-20261022.log`; UI results are in
`.runtime/ui-tests-20261022.log`, fleet observations in
`.runtime/mcp-live-20261022.log`. Runtime logs are not committed because they
may contain host-specific execution details.

Docker Desktop and the existing AI-OSOP PostgreSQL, Redis, Neo4j and Threat
Intel containers were started. Compose encountered an existing PostgreSQL
container-name conflict; existing containers were started directly. No schema
repair was performed. Running containers do not establish database schema
correctness or API readiness.

Local IaC analysis does not validate a live cloud account. Public reference
lookups do not prove target vulnerabilities. Go scanner declarations and
transport tests do not enable their disabled execution handlers. Signed
Task/Flow authority, provider execution, original evidence storage, and report
release still require their respective acceptance checks.

## Full-run failure identifiers

- tests/qualification/test_go_burp_disabled_fleet_boundaries_20261021.py::test_six_production_go_entrypoints_and_sdk_dispatch_are_one_inert_contract
- tests/qualification/test_go_burp_disabled_fleet_boundaries_20261021.py::test_cloud_and_turbo_deny_forged_approved_and_successful_calls[cloud-mcp]
- tests/qualification/test_mcp_eleven_execution_truth_20261021.py::test_startup_inventories_exact_eleven_but_no_registered_provider_is_qualified
- tests/qualification/test_mcp_external_native_boundaries_20261020.py::test_all_eleven_names_reach_real_registry_registration_source
- tests/qualification/test_mcp_external_native_boundaries_20261020.py::test_simulated_handlers_do_not_report_native_success[cloud-mcp]
- tests/qualification/test_mcp_external_native_boundaries_20261020.py::test_browser_production_bootstrap_requires_credentials_and_runtime
- tests/qualification/test_mcp_fleet_production_dispatch_contract_20261021.py::test_exact_eleven_main_registered_services_and_real_entrypoints
- tests/qualification/test_mcp_fleet_runtime_adversarial_20261021.py::test_eleven_live_registration_sources_route_to_expected_entrypoints
- tests/qualification/test_mcp_fleet_runtime_adversarial_20261021.py::test_actual_native_python_asgi_denies_unauthorized_execution_and_status
- tests/qualification/test_native_browser_local_playwright_20261020.py::test_actual_offline_chromium_signed_loopback_transport_and_journal
- tests/qualification/test_native_browser_local_playwright_20261020.py::test_native_signed_navigation_rejects_http_302_without_receipt
- tests/qualification/test_native_browser_local_playwright_20261020.py::test_native_signed_navigation_rejects_200_after_foreign_redirect_hop
- tests/qualification/test_subscription_ui_api_real_pg_contract_20261021.py::test_ui_exact_manual_ack_envelope_and_mounted_contract_offline
- tests/test_call_provenance.py::test_mcp_registry_emits_sanitized_correlated_success
- tests/test_call_provenance.py::test_mcp_error_status_counted_as_failure_without_leaking
- tests/test_diff_auth_report_promotion_fence.py::test_signed_provider_receipt_and_graph_flag_remain_candidate_unknown
- tests/test_diff_auth_report_promotion_fence.py::test_signed_diff_comparison_cannot_promote_through_source_result[candidate_review]
- tests/test_diff_auth_report_promotion_fence.py::test_signed_diff_comparison_cannot_promote_through_source_result[expected_denial_observed]
- tests/test_diff_auth_report_promotion_fence.py::test_signed_diff_comparison_cannot_promote_through_source_result[inconclusive]
- tests/test_diff_auth_report_promotion_fence.py::test_signed_diff_comparison_cannot_promote_through_source_result[unknown]
- tests/test_diff_auth_report_promotion_fence.py::test_signed_navigate_source_is_not_target_authority
- tests/test_durable_subscription_preparse_body_fence_20261021.py::test_six_actual_mounted_mutating_subscription_routes_use_preparse_fence
- tests/test_mcp_fleet_inventory_20261020.py::test_all_and_only_actual_main_registry_ids_are_in_inventory
- tests/test_mcp_fleet_inventory_20261020.py::test_config_defaults_match_registered_http_transport_ports
- tests/test_mcp_no_simulated_cloud_turbo_success_20261020.py::test_direct_http_execute_denies_all_tools_and_injected_credentials[cloud_mcp]
- tests/test_production_release_admission_20261021.py::test_unenrolled_fixture_signed_claim_denied_at_missing_committed_ledger
- tests/test_production_release_admission_20261021.py::test_missing_replica_and_target_owner_cannot_be_shortcut_by_acked_senior_row
- tests/test_production_release_admission_20261021.py::test_postawait_race_cannot_turn_stale_readback_into_permission[ack_lost]
- tests/test_production_release_admission_20261021.py::test_postawait_race_cannot_turn_stale_readback_into_permission[senior_revoked]
- tests/test_production_release_admission_20261021.py::test_postawait_race_cannot_turn_stale_readback_into_permission[manifest_changed]
- tests/test_production_release_admission_20261021.py::test_postawait_race_cannot_turn_stale_readback_into_permission[replica_key_rotated]
- tests/test_production_release_admission_20261021.py::test_postawait_race_cannot_turn_stale_readback_into_permission[report_signer_revoked]
- tests/test_qualification_scorecard_release_fences_20261021.py::test_original_legacy_certificate_has_prominent_noncertified_disclaimer
- tests/test_report_attestations_api.py::test_signed_bundle_owner_scoped_returns_only_safe_envelope_and_verified_provenance
- tests/test_report_attestations_api.py::test_durable_owner_role_boundaries[alice-operator-200]
- tests/test_report_attestations_api.py::test_durable_owner_role_boundaries[mallory-senior_operator-200]
- tests/test_report_evidence_release_fencing.py::test_legacy_signed_snapshot_remains_draft_only
- tests/test_report_evidence_release_fencing.py::test_v2_release_requires_signed_task_and_all_artifact_receipts
- tests/test_report_source_provenance_gate.py::test_complete_signed_task_evidence_and_provider_receipt_is_not_target_proof
- tests/test_report_source_provenance_gate.py::test_manual_or_unattributed_graph_finding_never_passes_release[source_task_id]
- tests/test_report_source_provenance_gate.py::test_manual_or_unattributed_graph_finding_never_passes_release[source_task_sha256]
- tests/test_report_source_provenance_gate.py::test_manual_or_unattributed_graph_finding_never_passes_release[source_event_id]
- tests/test_report_source_provenance_gate.py::test_manual_or_unattributed_graph_finding_never_passes_release[provider_receipt_sha256]
- tests/test_report_source_provenance_gate.py::test_manual_or_unattributed_graph_finding_never_passes_release[flow_id]
- tests/test_report_source_provenance_gate.py::test_manual_or_unattributed_graph_finding_never_passes_release[flow_revision]
- tests/test_report_source_provenance_gate.py::test_manual_or_unattributed_graph_finding_never_passes_release[authorization_version]
- tests/test_report_source_provenance_gate.py::test_manual_or_unattributed_graph_finding_never_passes_release[authorization_sha256]
- tests/test_report_source_provenance_gate.py::test_forged_or_unknown_provenance_does_not_admit_report_release[different_tenant]
- tests/test_report_source_provenance_gate.py::test_forged_or_unknown_provenance_does_not_admit_report_release[not_completed]
- tests/test_report_source_provenance_gate.py::test_forged_or_unknown_provenance_does_not_admit_report_release[wrong_evidence_digest]
- tests/test_report_source_provenance_gate.py::test_forged_or_unknown_provenance_does_not_admit_report_release[changed_source_assignment]
- tests/test_report_source_provenance_gate.py::test_forged_or_unknown_provenance_does_not_admit_report_release[wrong_flow_revision]
- tests/test_report_source_provenance_gate.py::test_forged_or_unknown_provenance_does_not_admit_report_release[revoked_flow]
- tests/test_report_source_provenance_gate.py::test_forged_or_unknown_provenance_does_not_admit_report_release[untrusted_signer]
- tests/test_report_source_provenance_gate.py::test_forged_or_unknown_provenance_does_not_admit_report_release[failed_provider]
- tests/test_report_source_provenance_gate.py::test_forged_or_unknown_provenance_does_not_admit_report_release[wrong_provider_receipt]
- tests/test_report_source_provenance_gate.py::test_forged_or_unknown_provenance_does_not_admit_report_release[wrong_dispatch_version]
- tests/test_report_source_provenance_gate.py::test_forged_or_unknown_provenance_does_not_admit_report_release[absent_event]
- tests/test_report_source_provenance_gate.py::test_forged_or_unknown_provenance_does_not_admit_report_release[postgres_unavailable]
- tests/test_report_source_provenance_gate.py::test_forged_or_unknown_provenance_does_not_admit_report_release[changed_after_proof]
- tests/test_report_source_provenance_gate.py::test_source_evidence_receipt_recheck_failure_blocks_release
- tests/test_report_source_provenance_gate.py::test_graph_source_lineage_cannot_be_added_or_changed_after_report_signature
- tests/test_report_source_provenance_gate.py::test_unattributed_vulnerability_remains_verifiable_as_noncertified_draft
- tests/test_sourcemap_grant_binding_migration_20261021.py::test_only_one_additive_0037_head_and_source_parent
- tests/test_sourcemap_native_grant_pair_migration_20261021.py::test_alembic_head_and_immediate_parent_are_exact
- tests/test_sourcemap_native_loopback_registration_20261020.py::test_source_map_registry_loopback_retains_existing_registration[localhost]
- tests/test_supervision_api.py::test_sse_frames_include_resume_cursor_and_filter
