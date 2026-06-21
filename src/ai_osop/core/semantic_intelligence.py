"""
V4.2A Semantic Intelligence Layer
Classifies UI actions and maps business intent.
"""

from typing import Any, Dict, List, Optional

from ai_osop.core.models import UISemanticElement, WorkflowIntent


class SemanticRiskCatalog:
    """
    Maps business actions to potential vulnerability classes.
    """

    ACTION_MAP = {
        "Delete": {
            "classification": "destructive",
            "impact": 9,
            "risks": ["idor", "unauthorized_destruction"],
        },
        "Remove": {"classification": "destructive", "impact": 8, "risks": ["idor"]},
        "Invite": {
            "classification": "privilege_management",
            "impact": 10,
            "risks": ["tenant_escape", "privilege_escalation"],
        },
        "Export": {
            "classification": "sensitive_data",
            "impact": 9,
            "risks": ["pii_exposure", "idor"],
        },
        "Generate": {
            "classification": "credential",
            "impact": 10,
            "risks": ["credential_exposure", "privilege_escalation"],
        },
        "Billing": {"classification": "financial", "impact": 8, "risks": ["unauthorized_access"]},
        "Upload": {
            "classification": "file_processing",
            "impact": 7,
            "risks": ["rce", "storage_misconfiguration"],
        },
    }

    @classmethod
    def classify(cls, label: str) -> Dict[str, Any]:
        """
        Classify a UI element based on its label.
        """
        for keyword, data in cls.ACTION_MAP.items():
            if keyword.lower() in label.lower():
                return data

        return {"classification": "generic", "impact": 3, "risks": []}


class IntentDetector:
    """
    Infers the high-level business system from semantic elements and workflows.
    """

    SYSTEM_KEYWORDS = {
        "Identity Management": ["user", "role", "permission", "invite", "login", "password"],
        "Financial/Billing": ["billing", "invoice", "payment", "subscription", "refund"],
        "Data Administration": ["export", "import", "database", "settings", "organization"],
        "Asset Management": ["project", "ticket", "asset", "inventory"],
    }

    @classmethod
    def detect_system(cls, elements: List[UISemanticElement]) -> Optional[str]:
        """
        Heuristically detect the business system based on UI labels.
        """
        counts = {sys: 0 for sys in cls.SYSTEM_KEYWORDS}

        for el in elements:
            for sys, keywords in cls.SYSTEM_KEYWORDS.items():
                if any(k in el.label.lower() for k in keywords):
                    counts[sys] += 1

        # Return the system with highest matches
        sorted_sys = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        if sorted_sys[0][1] > 0:
            return sorted_sys[0][0]
        return None
