"""
V4.5 Cloud Intelligence Catalog
Maps cloud resources to their potential risks and misconfigurations.
"""

from typing import Any, Dict, List


class CloudRiskCatalog:
    """
    Catalog of cloud resources and their associated risks.
    """

    RISK_MAP = {
        "storage_bucket": {
            "criticality": 9,
            "risks": ["public_access", "excessive_exposure", "sensitive_files"],
        },
        "database": {
            "criticality": 10,
            "risks": ["anonymous_access", "cross_tenant_access", "missing_encryption"],
        },
        "iam_role": {
            "criticality": 10,
            "risks": ["privilege_misconfiguration", "excessive_permissions", "assume_role_abuse"],
        },
        "function": {
            "criticality": 8,
            "risks": [
                "code_injection",
                "over_privileged_execution_role",
                "exposed_environment_variables",
            ],
        },
        "identity_provider": {
            "criticality": 9,
            "risks": ["weak_password_policy", "missing_mfa", "excessive_token_lifetimes"],
        },
    }

    @classmethod
    def get_risks(cls, resource_type: str) -> List[str]:
        """Get potential risks for a given cloud resource type."""
        entry = cls.RISK_MAP.get(resource_type.lower(), {})
        return entry.get("risks", [])

    @classmethod
    def get_criticality(cls, resource_type: str) -> int:
        """Get the base criticality score for a resource type."""
        entry = cls.RISK_MAP.get(resource_type.lower(), {})
        return entry.get("criticality", 5)
