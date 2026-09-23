"""Ollama local backend.

A second implementation of the same Provider interface, talking to a model
running locally. Its job is to prove the abstraction is real: the review
layer works against a hosted API or a local model with no code changes, only
config. No API key, no cost, no data leaving the machine.
"""

from __future__ import annotations

import os

from auditor.ai.providers.base import Provider, ProviderError, http_post_json

_DEFAULT_MODEL = "llama3.2"
_DEFAULT_HOST = "http://localhost:11434"


class OllamaProvider(Provider):
    name = "ollama"

    def __init__(self, model=None, host=None, timeout=120):
        self.model = model or os.environ.get("OLLAMA_MODEL") or _DEFAULT_MODEL
        self.host = (
            host or os.environ.get("OLLAMA_HOST") or _DEFAULT_HOST
        ).rstrip("/")
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        url = f"{self.host}/api/generate"
        payload = {"model": self.model, "prompt": prompt, "stream": False}
        data = http_post_json(url, payload, timeout=self.timeout)
        return _extract_text(data)


def _extract_text(data) -> str:
    if not isinstance(data, dict) or "response" not in data:
        raise ProviderError(f"unexpected Ollama response shape: {data!r}"[:200])
    text = data["response"]
    if not isinstance(text, str) or not text.strip():
        raise ProviderError("Ollama returned an empty response")
    return text
