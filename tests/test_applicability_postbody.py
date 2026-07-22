"""ApplicabilityEngine must treat a POST body (`data`) as an injectable vector.

JS-001 regression: a login SQLi scan dispatched with a body but no explicit
method defaulted to GET and was skipped as "no input parameters", so sqlmap
never ran. A present `data` body is an injectable vector regardless of verb.
"""

from __future__ import annotations

from ai_osop.core.applicability import ApplicabilityEngine
from ai_osop.core.enums import VulnClass


def test_sqli_with_post_body_data_is_applicable_without_method():
    payload = {
        "url": "http://localhost:3000/rest/user/login",
        "data": "email=a@a.com&password=b",  # POST body, no explicit method
    }
    res = ApplicabilityEngine.is_applicable(VulnClass.SQLI, payload)
    assert res["applicable"] is True, res


def test_sqli_with_json_post_body_is_applicable():
    payload = {
        "url": "http://localhost:3000/rest/user/login",
        "data": '{"email":"a*","password":"b"}',
    }
    assert ApplicabilityEngine.is_applicable(VulnClass.SQLI, payload)["applicable"] is True


def test_sqli_get_without_params_or_body_still_skipped():
    payload = {"url": "http://localhost:3000/about"}  # no query, no body, GET
    res = ApplicabilityEngine.is_applicable(VulnClass.SQLI, payload)
    assert res["applicable"] is False


def test_sqli_get_with_query_params_still_applicable():
    payload = {"url": "http://localhost:3000/rest/products/search?q=test"}
    assert ApplicabilityEngine.is_applicable(VulnClass.SQLI, payload)["applicable"] is True
