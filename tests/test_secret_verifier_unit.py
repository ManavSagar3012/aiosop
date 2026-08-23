from ai_osop.core.secret_verifier import SECRET_PROVIDERS, classify_secret


def test_classify_github_token():
    assert classify_secret("ghp_" + "A" * 36) == "github"
    assert classify_secret("github_pat_" + "x" * 30) == "github"


def test_classify_stripe_live_key():
    assert classify_secret("sk_live_" + "0" * 24) == "stripe"


def test_classify_gitlab_pat():
    assert classify_secret("glpat-" + "x" * 20) == "gitlab"


def test_classify_unknown_returns_none():
    assert classify_secret("just-a-random-string") is None
    assert classify_secret("") is None


def test_all_providers_use_readonly_paths():
    # Safety invariant: liveness checks must never mutate. Allowed verbs: GET only.
    for name, p in SECRET_PROVIDERS.items():
        assert p["method"] == "GET", f"{name} must use GET (read-only)"
