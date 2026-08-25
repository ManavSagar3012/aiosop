"""Launcher: forces correct config, no reload."""
import os
import sys

# Force Ollama as primary (OpenRouter account has no credits)
os.environ["OSOP_LLM_PRIMARY_MODEL"] = "ollama/phi3:latest"
os.environ["OSOP_LLM_FALLBACK_MODEL"] = "ollama/phi3:latest"
os.environ["OSOP_MOCK_LLM"] = "false"
os.environ["OSOP_LLM_OLLAMA_NUM_CTX"] = "4096"

if __name__ == "__main__":
    from ai_osop.core.config import settings
    print(f"[launcher] Primary: {settings.llm_primary_model}")
    print(f"[launcher] Fallback: {settings.llm_fallback_model}")
    print(f"[launcher] num_ctx: {settings.llm_ollama_num_ctx}")
    print(f"[launcher] Mock: {settings.mock_llm}")
    
    import uvicorn
    uvicorn.run(
        "ai_osop.api.main:app",
        host="127.0.0.1",
        port=8200,
        reload=False,
    )
