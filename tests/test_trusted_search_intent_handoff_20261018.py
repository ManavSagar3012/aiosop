"""Signed-scope research intent handoff is a citation queue, not a finding."""

import pytest

from ai_osop.core.trusted_search import (
    TrustedSearchIntent,
    _bounded_research_handoff,
)


def test_research_citations_bounded_provenance_and_unknown():
    sources = [
        {
            "url": f"https://example.com/{i}",
            "title": f"Indexed {i}",
            "untrusted_snippet": "Unverified historical claim",
            "tool": "web_search",
            "engine": "searxng",
        }
        for i in range(25)
    ]
    result = _bounded_research_handoff(TrustedSearchIntent.RESEARCH, sources)
    handoff = result["research_handoff"]
    assert len(handoff["lead_notes"]) == 10
    assert handoff["answer_status"] == "unverified_excerpts_only"
    assert handoff["requires_independent_source_verification"] is True
    assert handoff["not_an_answer"] is True
    assert handoff["finding_verified"] is False
    assert all(
        n["verification"] == "UNKNOWN"
        and n["reportable"] is False
        and n["citation_sha256"]
        and n["origin_engine"] == "searxng"
        for n in handoff["lead_notes"]
    )


def test_answer_and_empty_research_never_synthesize():
    assert _bounded_research_handoff(TrustedSearchIntent.LINKS, []) == {}
    assert (
        _bounded_research_handoff(TrustedSearchIntent.ANSWER, [])["research_handoff"][
            "answer_status"
        ]
        == "UNKNOWN"
    )
    assert (
        _bounded_research_handoff(
            TrustedSearchIntent.ANSWER,
            [
                {
                    "url": "https://example.com/a",
                    "title": "",
                    "untrusted_snippet": "",
                    "tool": "web_search",
                    "engine": "searxng",
                }
            ],
        )["research_handoff"]["lead_notes"]
        == []
    )
