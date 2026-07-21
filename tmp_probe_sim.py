import sys
from pathlib import Path
sys.path.insert(0, str(Path('.').resolve() / 'benchmarks'))
from score_engagement import _finding_is_simulated
from ai_osop.core.config import Severity, VulnClass
from ai_osop.core.models import Vulnerability

v = Vulnerability(
    id="v1", cwe="CWE-89", vuln_type=VulnClass.SQLI, severity=Severity.HIGH,
    title="x", description="x", tool_source="deterministic_scan",
    confidence=0.9, engagement_id="e1",
)
print("is_simulated attr:", getattr(v, "is_simulated", "MISSING"))
print("type:", type(getattr(v, "is_simulated")))
print("_finding_is_simulated:", _finding_is_simulated(v))
print("v.is_simulated():", v.is_simulated())
