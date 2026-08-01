"""Characterization tests for recon_agent.SimpleHTMLParser — the pure link /
script / form extractor that seeds the recon endpoint pipeline.

Previously untested (normalize_endpoint_url is covered by
test_recon_endpoint_hygiene). These pin the extraction contract: which tags
produce endpoints, how form inputs bind to their enclosing form, and the
state-machine quirks (inputs outside a form, or after </form>, are dropped).
"""

from ai_osop.agents.recon_agent import SimpleHTMLParser


def _parse(html: str) -> SimpleHTMLParser:
    p = SimpleHTMLParser()
    p.feed(html)
    return p


def test_extracts_anchor_hrefs_and_script_srcs():
    p = _parse(
        '<a href="/a">x</a><a href="https://ex.com/b">y</a>'
        '<script src="/app.js"></script><script>inline()</script>'
    )
    assert p.links == ["/a", "https://ex.com/b"]
    assert p.scripts == ["/app.js"]  # inline <script> (no src) is ignored


def test_anchor_without_href_and_script_without_src_are_ignored():
    p = _parse('<a>no href</a><script>no src</script>')
    assert p.links == []
    assert p.scripts == []


def test_form_captures_action_method_and_named_inputs():
    p = _parse(
        '<form action="/login" method="post">'
        '<input name="user"><input name="pass"><input type="submit">'
        "</form>"
    )
    assert len(p.forms) == 1
    f = p.forms[0]
    assert f["action"] == "/login"
    assert f["method"] == "POST"  # method is upper-cased
    assert f["inputs"] == ["user", "pass"]  # the unnamed submit input is skipped


def test_form_method_defaults_to_get():
    p = _parse('<form action="/search"><input name="q"></form>')
    assert p.forms[0]["method"] == "GET"


def test_inputs_outside_a_form_are_dropped():
    p = _parse(
        '<input name="loose">'
        '<form action="/f"><input name="in"></form>'
        '<input name="after">'
    )
    # Only the input inside the open form binds; loose + post-close are dropped.
    assert [f["inputs"] for f in p.forms] == [["in"]]


def test_multiple_forms_route_inputs_to_their_own_form():
    p = _parse(
        '<form action="/one"><input name="a"></form>'
        '<form action="/two"><input name="b"><input name="c"></form>'
    )
    assert [f["action"] for f in p.forms] == ["/one", "/two"]
    assert p.forms[0]["inputs"] == ["a"]
    assert p.forms[1]["inputs"] == ["b", "c"]
