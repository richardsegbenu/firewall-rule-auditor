"""Google AI Studio (Gemini) backend.

Uses the free-tier Generative Language REST endpoint directly rather than a
vendor SDK, which keeps the dependency surface small and the request shape
visible. The API key is read from the environment, never hard-coded.
"""

from __future__ import annotations

import os

from auditor.ai.providers.base import Provider, ProviderError, http_post_json

_DEFAULT_MODEL = "gemini-1.5-flash"
_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiProvider(Provider):
    name = "gemini"

    def __init__(self, api_key=None, model=None, timeout=30):
        self.api_key = (
            api_key
            or os.environ.get("GEMINI_API_KEY")
            or os.environ.get("GOOGLE_API_KEY")
        )
        if not self.api_key:
            raise ProviderError(
                "no Gemini API key: set GEMINI_API_KEY in the environment"
            )
        self.model = model or os.environ.get("GEMINI_MODEL") or _DEFAULT_MODEL
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        url = f"{_BASE_URL}/{self.model}:generateContent?key={self.api_key}"
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        data = http_post_json(url, payload, timeout=self.timeout)
        return _extract_text(data)


def _extract_text(data) -> str:
    if not isinstance(data, dict):
        raise ProviderError(f"unexpected Gemini response: {data!r}"[:200])

    candidates = data.get("candidates")
    if not candidates:
        feedback = data.get("promptFeedback", {})
        reason = feedback.get("blockReason")
        if reason:
            raise ProviderError(f"Gemini blocked the prompt: {reason}")
        raise ProviderError("Gemini returned no candidates")

    try:
        parts = candidates[0]["content"]["parts"]
        text = "".join(part.get("text", "") for part in parts)
    except (KeyError, IndexError, TypeError) as exc:
        raise ProviderError(f"unexpected Gemini response shape: {exc}") from exc

    if not text.strip():
        raise ProviderError("Gemini returned an empty response")
    return text
