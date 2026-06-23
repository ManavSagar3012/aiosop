import json
import re
from typing import Any, Dict, List, Optional
import structlog
from ai_osop.core.models import DiffAuthFinding

logger = structlog.get_logger("ai_osop.findings_quality")


class FindingQualityEngine:
    """
    Sprint 7: Evaluates, scores, and refines differential authorization findings.
    Suppresses false positives (static assets, 200 OK with error body) and
    calculates exact confidence and business impact metrics.
    """

    STATIC_PATH_PATTERNS = re.compile(
        r"\.(css|js|png|jpg|jpeg|gif|svg|woff2?|ico|html|txt|json)$|/(static|assets|chunks|webpack|vendor)/",
        re.IGNORECASE
    )

    ERROR_KEY_PATTERNS = {
        "error", "err", "message", "msg", "status", "success", "code", "exception"
    }

    ERROR_VAL_PATTERNS = re.compile(
        r"denied|forbidden|unauthorized|unauthenticated|error|fail|invalid|expired|login|signin|bad request|not allowed",
        re.IGNORECASE
    )

    SENSITIVE_FIELD_PATTERNS = {
        "critical": re.compile(r"password|token|secret|key|private|apikey|hash|salt|card|cvv|cc_", re.IGNORECASE),
        "high": re.compile(r"ssn|tax|national_id|phone|email|address|billing|passport", re.IGNORECASE),
        "medium": re.compile(r"username|nickname|avatar|profile|settings|created_at|updated_at", re.IGNORECASE),
    }

    @classmethod
    def evaluate_finding(
        cls,
        finding: DiffAuthFinding,
        body_a: Any,
        body_b: Any,
        url_path: str
    ) -> Dict[str, Any]:
        """
        Assess finding quality, suppress false positives, and calculate confidence & impact.
        Returns a dict:
          - "suppressed": bool
          - "confidence_score": float
          - "impact_score": str (critical, high, medium, low)
          - "reasons": list of strings
        """
        reasons = []
        suppressed = False

        # 1. Suppress Static Resource paths
        if url_path and cls.STATIC_PATH_PATTERNS.search(url_path):
            suppressed = True
            reasons.append("static_resource_path")

        # 2. Suppress 200 OK but containing access denied / error bodies
        if isinstance(body_b, dict):
            # Check if any error/denied terms appear in error-related keys
            for k, v in body_b.items():
                if k.lower() in cls.ERROR_KEY_PATTERNS and isinstance(v, str):
                    if cls.ERROR_VAL_PATTERNS.search(v):
                        suppressed = True
                        reasons.append("error_body_swallowed_in_200_ok")
                        break
            
            # Suppress empty or trivial dicts
            if not body_b or list(body_b.keys()) == ["success"] and body_b.get("success") is False:
                suppressed = True
                reasons.append("empty_or_failed_status_body")

        elif isinstance(body_b, list):
            if len(body_b) == 0:
                suppressed = True
                reasons.append("empty_array_response")

        # 3. Ownership Verification Check
        # Check if values from body_a are leaked inside body_b
        a_elements_in_b = []
        ownership_verified = False
        
        def check_leakage(val_a, body_b_serialized):
            nonlocal ownership_verified
            if isinstance(val_a, (str, int)) and len(str(val_a)) > 3:
                val_str = str(val_a)
                # Ignore common keys/generic boolean values/very short strings
                if val_str.lower() not in ("true", "false", "null", "none", "unknown", "pending", "completed"):
                    if val_str in body_b_serialized:
                        ownership_verified = True
                        a_elements_in_b.append(val_str)
            elif isinstance(val_a, dict):
                for k, v in val_a.items():
                    # Focus on identifiers, emails, names
                    if k in ("id", "email", "username", "name", "phone", "tenant_id", "user_id"):
                        check_leakage(v, body_b_serialized)
            elif isinstance(val_a, list):
                for item in val_a:
                    check_leakage(item, body_b_serialized)

        body_b_str = json.dumps(body_b) if not isinstance(body_b, str) else body_b
        check_leakage(body_a, body_b_str)

        # 4. Calculate Confidence Score
        confidence = finding.confidence
        if ownership_verified:
            confidence = max(confidence, 0.95)
        elif "unconfirmed" in finding.category:
            confidence = min(confidence, 0.4)
        
        if suppressed:
            confidence = 0.0

        # 5. Calculate Business Impact (based on exposed fields)
        impact = "low"
        body_keys = []
        if isinstance(body_b, dict):
            body_keys = list(body_b.keys())
        elif isinstance(body_b, list) and len(body_b) > 0 and isinstance(body_b[0], dict):
            body_keys = list(body_b[0].keys())

        # Evaluate exposed keys sensitivity
        for key in body_keys:
            if cls.SENSITIVE_FIELD_PATTERNS["critical"].search(key):
                impact = "critical"
                break
            elif cls.SENSITIVE_FIELD_PATTERNS["high"].search(key):
                impact = "high"
            elif cls.SENSITIVE_FIELD_PATTERNS["medium"].search(key) and impact == "low":
                impact = "medium"

        # Escalate impact if ownership of A was verified in B's response (IDOR)
        if ownership_verified and impact == "low":
            impact = "high"

        return {
            "suppressed": suppressed,
            "confidence_score": confidence,
            "impact_score": impact,
            "ownership_verified": ownership_verified,
            "verified_elements": list(set(a_elements_in_b)),
            "reasons": reasons,
        }
