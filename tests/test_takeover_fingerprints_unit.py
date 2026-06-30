from ai_osop.core.takeover_fingerprints import match_takeover


def test_detects_s3_unclaimed():
    m = match_takeover("assets.example.com",
                       cnames=["assets.example.com.s3.amazonaws.com"],
                       body="<Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message>")
    assert m and m["service"] == "AWS S3"


def test_detects_github_pages_unclaimed():
    m = match_takeover("blog.example.com", cnames=["example.github.io"],
                       body="<h1>404</h1><p>There isn't a GitHub Pages site here.</p>")
    assert m and m["service"] == "GitHub Pages"


def test_detects_heroku_no_such_app():
    m = match_takeover("app.example.com", cnames=["example.herokuapp.com"],
                       body="No such app\nherokucdn.com/error-pages/no-such-app.html")
    assert m and m["service"] == "Heroku"


def test_no_match_on_normal_page():
    m = match_takeover("www.example.com", cnames=[], body="<html><body>Welcome to our site</body></html>")
    assert m is None


def test_generic_404_alone_is_not_a_takeover():
    # A bare 404 without a service-specific unclaimed signature must NOT match
    # (false positives get reports rejected).
    m = match_takeover("x.example.com", cnames=[], body="<h1>404 Not Found</h1>")
    assert m is None
