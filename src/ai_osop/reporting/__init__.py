"""AI-OSOP Reporting Package

Certificate generators, report exporters, and the bounty-report rendering
engine for engagement output.

BLK-3 (2026-07-22): the audit flagged ``reporting/`` as a 75-line vestigial
stub. The REAL bounty report engine lives in ``core/bounty_report.py`` (229L:
triager-grade Markdown report rendering, dedup signatures, simulated-finding
guards) and ``core/poc_generator.py`` (334L: per-class PoC artifact generation
for SQLi/XSS/SSRF/JWT/mass-assign/race/CSRF/subdomain-takeover). This package
now re-exports them so ``from ai_osop.reporting import render_bounty_report``
is the canonical import path, and ``reporting/exporters.py`` is clearly marked
as the legacy Jinja2/HTML exporter (not the bounty engine).
"""

from ai_osop.core.bounty_report import (
    finding_signature,
    render_bounty_report,
)
from ai_osop.core.findings_quality import (
    AttackSurfaceCertifier,
    FindingCertificationEngine,
    FindingConversionEngine,
)
from ai_osop.core.poc_generator import (
    PoCArtifact,
    generate_poc,
    render_poc_markdown,
)

__all__ = [
    "FindingCertificationEngine",
    "AttackSurfaceCertifier",
    "FindingConversionEngine",
    "render_bounty_report",
    "finding_signature",
    "generate_poc",
    "render_poc_markdown",
    "PoCArtifact",
]
