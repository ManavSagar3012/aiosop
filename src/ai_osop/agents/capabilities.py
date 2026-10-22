"""Explicit implemented task declarations; unknown agent classes default deny."""

AGENT_TASK_TYPES: dict[str, frozenset[str]] = {
    "ReconAgent": frozenset(
        {
            "dns_enumeration",
            "port_scan",
            "service_probe",
            "osint_lookup",
            "technology_fingerprint",
            "full_recon",
        }
    ),
    "VulnAnalysisAgent": frozenset(
        {"burp_scan", "intruder_fuzz", "nuclei_scan", "correlate_findings", "triage_finding"}
    ),
    "GraphQLAgent": frozenset({"gql_discover_schema", "gql_find_hidden", "gql_test_authorization"}),
    "JSAnalyzerAgent": frozenset({"analyze_js"}),
    "MobileAnalysisAgent": frozenset(),
    "NextJSSpecialistAgent": frozenset(),
    "CloudSpecialistAgent": frozenset({"scan_local_iac", "analyze_iam"}),
    "ReactSpecialistAgent": frozenset({"analyze_bundle"}),
    "CodeQLAgent": frozenset({"ingest_sarif", "map_sast_to_graph"}),
    "StatefulLogicAgent": frozenset({"map_business_process"}),
    "VisualContextAgent": frozenset({"analyze_screenshot", "compare_views"}),
    "ExploitValidationAgent": frozenset({"validate_exploit", "exploit_validation"}),
    "AttackChainAgent": frozenset(
        {"discover_paths", "validate_chain", "propagate_risk", "find_lateral_movement"}
    ),
    "PayloadMutationAgent": frozenset(
        {"generate_payloads", "mutate_payload", "evolve_population", "process_feedback"}
    ),
    "ContextManagerAgent": frozenset(
        {"summarize_context", "retrieve_context", "compact_context", "store_context_snapshot"}
    ),
    "HumanOversightAgent": frozenset({"evaluate_risk", "format_approval"}),
    "ConcurrencyAgent": frozenset({"test_race_condition", "test_state_machine_bypass"}),
    "StackProfilerAgent": frozenset({"profile_stack"}),
    "ReportingAgent": frozenset({"generate_report", "compile_evidence"}),
    "PlaywrightAgent": frozenset(
        {
            "navigate",
            "authenticate",
            "map_workflow",
            "replay_for_diff_auth",
            "extract_semantics",
            "capture_session",
            "capture_authenticated_surface",
            "extract_har_api_inventory",
            "run_diff_auth_analysis",
            "map_business_logic",
        }
    ),
}
