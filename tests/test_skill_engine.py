"""
AIOSOP-AUDIT-2026-06-16 tests for SkillEngine persistence + dead-id resolution.

Guards two fixes:
  - usage/reputation counters now survive restarts (were in-memory only -> reset).
  - dead TASK_SKILL_MAP ids resolve to real skills via tag search (were silent no-ops).
"""

import os

from ai_osop.core.skill_engine import SkillEngine


def _make_skills(tmp_path):
    d = tmp_path / "skills"
    d.mkdir()
    (d / "idor_testing.md").write_text(
        "---\nname: IDOR Testing\ntags: [idor, bola, access]\n---\nbody about idor",
        encoding="utf-8",
    )
    (d / "xxe_injection.md").write_text(
        "---\nname: XXE Injection\ntags: [xxe, xml]\n---\nbody about xxe",
        encoding="utf-8",
    )
    return str(d)


def test_resolve_ids_substitutes_dead_and_drops_garbage(tmp_path):
    sd = _make_skills(tmp_path)
    e = SkillEngine(sd, stats_path=str(tmp_path / "stats.json"))
    resolved = e.resolve_ids(["idor_testing", "xxe", "totally_unknown_zzz"])
    assert "idor_testing" in resolved  # real id kept
    assert "xxe_injection" in resolved  # dead id 'xxe' -> real skill via tags
    assert len(resolved) == 2  # garbage id dropped, not mapped arbitrarily


def test_stats_persist_across_instances(tmp_path):
    sd = _make_skills(tmp_path)
    sp = str(tmp_path / "stats.json")

    e1 = SkillEngine(sd, stats_path=sp)
    e1.record_execution("idor_testing", "agent-1", reason="t", stage="execution")
    e1.record_execution("idor_testing", "agent-1", reason="t", stage="verification")
    assert e1.skills["idor_testing"]["usage_count"] == 1
    assert e1.skills["idor_testing"]["verified_findings"] == 1
    assert os.path.exists(sp)

    # A fresh engine (simulating a restart) loads the persisted counters.
    e2 = SkillEngine(sd, stats_path=sp)
    assert e2.skills["idor_testing"]["usage_count"] == 1
    assert e2.skills["idor_testing"]["verified_findings"] == 1


def test_reputation_survives_restart(tmp_path):
    sd = _make_skills(tmp_path)
    sp = str(tmp_path / "stats.json")
    e1 = SkillEngine(sd, stats_path=sp)
    # Drive a full effective cycle so reputation is > 0.
    e1.record_execution("idor_testing", "a", reason="r", stage="execution")
    e1.record_execution("idor_testing", "a", reason="r", stage="verification")
    e1.record_execution("idor_testing", "a", reason="r", stage="acceptance", payout=500.0)
    rep1 = e1.get_skill_reputation("idor_testing")
    assert rep1 > 0

    e2 = SkillEngine(sd, stats_path=sp)
    assert e2.get_skill_reputation("idor_testing") == rep1
