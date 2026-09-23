"""Tests for the AI provider backends.

No network: the HTTP boundary is mocked, so these tests check request
building and response parsing, not connectivity.
"""

import pytest

from auditor.ai.providers import (
    GeminiProvider,
    OllamaProvider,
    Provider,
    ProviderError,
    available_providers,
    get_provider,
)


# --- factory -------------------------------------------------------------


def test_available_providers_lists_both():
    assert available_providers() == ["gemini", "ollama"]


def test_get_provider_unknown_raises():
    with pytest.raises(ProviderError):
        get_provider("does-not-exist")


def test_get_provider_defaults_to_gemini(monkeypatch):
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    provider = get_provider()
    assert isinstance(provider, GeminiProvider)
    assert provider.name == "gemini"


def test_get_provider_reads_env(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "ollama")
    provider = get_provider()
    assert isinstance(provider, OllamaProvider)


def test_providers_share_interface(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    assert isinstance(GeminiProvider(), Provider)
    assert isinstance(OllamaProvider(), Provider)


# --- gemini --------------------------------------------------------------


def test_gemini_requires_api_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with pytest.raises(ProviderError):
        GeminiProvider()


def test_gemini_generate_parses_text(monkeypatch):
    captured = {}

    def fake_post(url, payload, headers=None, timeout=30):
        captured["url"] = url
        captured["payload"] = payload
        return {"candidates": [{"content": {"parts": [{"text": "hello world"}]}}]}

    monkeypatch.setattr("auditor.ai.providers.gemini.http_post_json", fake_post)
    provider = GeminiProvider(api_key="k", model="gemini-test")
    result = provider.generate("prompt text")
    assert result == "hello world"
    assert "gemini-test:generateContent" in captured["url"]
    assert "key=k" in captured["url"]
    assert captured["payload"]["contents"][0]["parts"][0]["text"] == "prompt text"


def test_gemini_empty_response_raises(monkeypatch):
    def fake_post(url, payload, headers=None, timeout=30):
        return {"candidates": [{"content": {"parts": [{"text": "   "}]}}]}

    monkeypatch.setattr("auditor.ai.providers.gemini.http_post_json", fake_post)
    with pytest.raises(ProviderError):
        GeminiProvider(api_key="k").generate("x")


def test_gemini_blocked_prompt_raises(monkeypatch):
    def fake_post(url, payload, headers=None, timeout=30):
        return {"promptFeedback": {"blockReason": "SAFETY"}}

    monkeypatch.setattr("auditor.ai.providers.gemini.http_post_json", fake_post)
    with pytest.raises(ProviderError):
        GeminiProvider(api_key="k").generate("x")


def test_gemini_bad_shape_raises(monkeypatch):
    def fake_post(url, payload, headers=None, timeout=30):
        return {"nonsense": True}

    monkeypatch.setattr("auditor.ai.providers.gemini.http_post_json", fake_post)
    with pytest.raises(ProviderError):
        GeminiProvider(api_key="k").generate("x")


# --- ollama --------------------------------------------------------------


def test_ollama_generate_parses_text(monkeypatch):
    captured = {}

    def fake_post(url, payload, headers=None, timeout=30):
        captured["url"] = url
        captured["payload"] = payload
        return {"response": "local answer"}

    monkeypatch.setattr("auditor.ai.providers.ollama.http_post_json", fake_post)
    provider = OllamaProvider(model="llama-test", host="http://localhost:11434")
    result = provider.generate("prompt text")
    assert result == "local answer"
    assert captured["url"].endswith("/api/generate")
    assert captured["payload"]["model"] == "llama-test"
    assert captured["payload"]["stream"] is False


def test_ollama_empty_response_raises(monkeypatch):
    def fake_post(url, payload, headers=None, timeout=30):
        return {"response": ""}

    monkeypatch.setattr("auditor.ai.providers.ollama.http_post_json", fake_post)
    with pytest.raises(ProviderError):
        OllamaProvider().generate("x")


def test_ollama_bad_shape_raises(monkeypatch):
    def fake_post(url, payload, headers=None, timeout=30):
        return {"unexpected": 1}

    monkeypatch.setattr("auditor.ai.providers.ollama.http_post_json", fake_post)
    with pytest.raises(ProviderError):
        OllamaProvider().generate("x")
