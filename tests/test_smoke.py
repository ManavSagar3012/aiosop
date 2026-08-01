from ai_osop.core.config import settings
from ai_osop.core.llm import LiteLLMClient
from ai_osop.payload_engine.engine import EncodingPipeline


def test_settings_load_mcp_defaults():
    assert settings.burp_mcp_host == "127.0.0.1"
    assert settings.nuclei_mcp_port == 8084


def test_litellm_client_uses_configured_models():
    client = LiteLLMClient()
    assert client.primary_model == settings.llm_primary_model
    assert client.fallback_model == settings.llm_fallback_model


def test_unicode_encoding_pipeline():
    assert EncodingPipeline.apply("AZ", ["unicode"]) == "\\u0041\\u005a"


def test_evidence_receipts_flag_defaults_off():
    from ai_osop.core.config import Settings

    s = Settings()
    assert s.evidence_receipts_enabled is False
    assert s.evidence_root == "./evidence"
