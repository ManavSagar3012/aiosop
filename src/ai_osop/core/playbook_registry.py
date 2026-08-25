"""Playbook Registry (T1.4)

Extensible registry for validation playbooks. New playbooks can be added
by registering a callable against a vulnerability category without
modifying the ValidationEngine class.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

logger = logging.getLogger("ai_osop.core.playbook_registry")


@dataclass
class PlaybookEntry:
    """Registered playbook metadata."""

    name: str
    handler: Callable[..., Coroutine[Any, Any, Any]]
    categories: Set[str]
    description: str = ""
    requires_tools: Set[str] = field(default_factory=set)
    timeout_seconds: float = 15.0


class PlaybookRegistry:
    """Central registry for validation playbooks.

    Usage:
        registry = PlaybookRegistry()
        registry.register(
            name="xss_reflection_check",
            handler=my_xss_handler,
            categories={"xss", "cross_site_scripting"},
            description="Check if reflected XSS payload appears in response",
        )

        playbook = registry.resolve("xss")
        if playbook:
            outcome = await playbook.handler(hyp)
    """

    def __init__(self) -> None:
        self._playbooks: Dict[str, PlaybookEntry] = {}
        self._category_index: Dict[str, str] = {}  # category -> playbook name

    def register(
        self,
        name: str,
        handler: Callable[..., Coroutine[Any, Any, Any]],
        categories: Set[str],
        description: str = "",
        requires_tools: Optional[Set[str]] = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        """Register a new playbook."""
        entry = PlaybookEntry(
            name=name,
            handler=handler,
            categories=categories,
            description=description,
            requires_tools=requires_tools or set(),
            timeout_seconds=timeout_seconds,
        )
        self._playbooks[name] = entry
        for cat in categories:
            if cat in self._category_index:
                logger.warning(
                    "playbook_category_overlap category=%s existing=%s new=%s",
                    cat,
                    self._category_index[cat],
                    name,
                )
            self._category_index[cat.lower()] = name
        logger.debug("playbook_registered name=%s categories=%s", name, categories)

    def resolve(self, category_or_name: str) -> Optional[PlaybookEntry]:
        """Resolve a playbook by category name or exact playbook name."""
        # Try exact name match first
        if category_or_name in self._playbooks:
            return self._playbooks[category_or_name]
        # Try category lookup
        playbook_name = self._category_index.get(category_or_name.lower())
        if playbook_name:
            return self._playbooks.get(playbook_name)
        return None

    def resolve_all(self, categories: Set[str]) -> List[PlaybookEntry]:
        """Resolve all playbooks matching any of the given categories."""
        seen = set()
        results = []
        for cat in categories:
            entry = self.resolve(cat)
            if entry and entry.name not in seen:
                seen.add(entry.name)
                results.append(entry)
        return results

    def list_all(self) -> List[PlaybookEntry]:
        """List all registered playbooks."""
        return list(self._playbooks.values())

    def list_categories(self) -> Dict[str, str]:
        """Return category -> playbook name mapping."""
        return dict(self._category_index)


# Global singleton
_registry: Optional[PlaybookRegistry] = None


def get_playbook_registry() -> PlaybookRegistry:
    """Get or create the global playbook registry."""
    global _registry
    if _registry is None:
        _registry = PlaybookRegistry()
        _register_default_playbooks(_registry)
    return _registry


def _register_default_playbooks(registry: PlaybookRegistry) -> None:
    """Register the built-in playbooks."""
    # These are registered lazily to avoid circular imports
    # The actual handlers are wired up when the validation engine initializes
    from ai_osop.core.validation_playbooks import (
        handle_xss_reflection,
        handle_ssrf_oast,
        handle_idor_differential,
        handle_mass_assignment,
        handle_ssti_template,
        handle_cors_misconfiguration,
        handle_open_redirect,
        handle_header_injection,
        handle_xxe_external_entity,
        handle_csrf_token_missing,
    )

    builtins = [
        ("xss_reflection", handle_xss_reflection, {"xss", "cross_site_scripting", "reflected_xss"}),
        ("ssrf_oast", handle_ssrf_oast, {"ssrf", "server_side_request_forgery"}),
        ("idor_differential", handle_idor_differential, {"idor", "broken_access_control", "authorization"}),
        ("mass_assignment", handle_mass_assignment, {"mass_assignment", "over_posting"}),
        ("ssti_template", handle_ssti_template, {"ssti", "server_side_template_injection"}),
        ("cors_misconfiguration", handle_cors_misconfiguration, {"cors", "cors_misconfiguration"}),
        ("open_redirect", handle_open_redirect, {"open_redirect", "url_redirect"}),
        ("header_injection", handle_header_injection, {"header_injection", "response_splitting"}),
        ("xxe_external_entity", handle_xxe_external_entity, {"xxe", "xml_external_entity"}),
        ("csrf_token_missing", handle_csrf_token_missing, {"csrf", "cross_site_request_forgery"}),
    ]

    for name, handler, categories in builtins:
        registry.register(
            name=name,
            handler=handler,
            categories=categories,
            description=f"Built-in playbook: {name}",
        )
