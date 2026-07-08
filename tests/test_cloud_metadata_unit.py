from ai_osop.core.cloud_metadata import IMDS_TARGETS, extract_credentials


def test_extracts_aws_imds_credentials():
    body = (
        '{"Code":"Success","AccessKeyId":"ASIAEXAMPLE12345","SecretAccessKey":'
        '"abc/def+ghiSECRET","Token":"IQoJb3JpZ2luX2Vj...","Expiration":"2026-07-01"}'
    )
    creds = extract_credentials(body)
    assert creds and creds[0]["provider"] == "aws"
    # raw secret must never be surfaced in full
    assert "abc/def+ghiSECRET" not in creds[0]["redacted"]


def test_extracts_gcp_token():
    body = '{"access_token":"ya29.A0ARrEXAMPLE","expires_in":3599,"token_type":"Bearer"}'
    creds = extract_credentials(body)
    assert creds and creds[0]["provider"] == "gcp"


def test_no_credentials_in_normal_body():
    assert extract_credentials("<html>welcome</html>") == []
    assert extract_credentials("") == []


def test_imds_targets_include_aws_role_path():
    assert any("169.254.169.254" in t and "iam" in t for t in IMDS_TARGETS)
