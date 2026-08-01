"""Sandbox policy table: sensible defaults + no silent misclassification."""

from ai_osop.safety.sandbox_policy import (
    TOOL_SANDBOX_CLASSES,
    describe_policy,
    requires_container,
    sandbox_class_for,
)


def test_unknown_tool_defaults_to_http_scoped():
    assert sandbox_class_for("never_heard_of_it") == "http_scoped"


def test_exploit_runners_need_full_isolation():
    assert sandbox_class_for("exploit_run") == "full_isolation"
    assert requires_container("exploit_run")


def test_active_probers_need_quota():
    assert sandbox_class_for("sqli_oracle") == "egress_quota"
    assert requires_container("sqli_oracle")


def test_reporting_is_noop_sandbox():
    assert sandbox_class_for("write_report") == "none"
    assert not requires_container("write_report")


def test_describe_policy_covers_keys():
    described = describe_policy()
    assert described["sqli_oracle"] == "egress_quota"
    assert "exploit_run" in described


def test_describe_policy_subset():
    described = describe_policy(["sqli_oracle", "unknown-thing"])
    assert described == {"sqli_oracle": "egress_quota", "unknown-thing": "http_scoped"}
