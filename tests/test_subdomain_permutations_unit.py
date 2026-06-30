from ai_osop.core.subdomain_permutations import generate_permutations, DEFAULT_WORDS


def test_generates_prefix_and_suffix_permutations():
    out = generate_permutations("example.com", ["api"], words=["dev", "staging"])
    assert "dev-api.example.com" in out
    assert "api-dev.example.com" in out
    assert "dev.example.com" in out
    assert "staging-api.example.com" in out


def test_numeric_increments():
    out = generate_permutations("example.com", ["api1"], words=[])
    assert "api2.example.com" in out  # api1 -> api2


def test_dedup_and_scope():
    out = generate_permutations("example.com", ["api", "api"], words=["dev"])
    # all candidates are within the base domain, no duplicates
    assert all(h.endswith(".example.com") for h in out)
    assert len(out) == len(set(out))


def test_default_words_present():
    assert "dev" in DEFAULT_WORDS and "staging" in DEFAULT_WORDS and "api" in DEFAULT_WORDS


def test_empty_known_uses_words_against_root():
    out = generate_permutations("example.com", [], words=["admin", "vpn"])
    assert "admin.example.com" in out and "vpn.example.com" in out
