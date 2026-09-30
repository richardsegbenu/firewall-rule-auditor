"""Response caching for the AI review layer.

Model calls are the slow, rate-limited, and (on a paid tier) expensive part
of this system. The same findings produce the same prompt, and the same
prompt should not be paid for twice.

The cache is content-addressed: the key is a hash of the provider, the
model, and the exact prompt. Change any of those and you get a different
key, so a cached response can never be served for a different question.

This is a wrapper around the Provider interface rather than a change to any
backend. Every backend gets caching at once, and neither Gemini nor Ollama
knows the cache exists.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from auditor.ai.providers import Provider

_DEFAULT_DIR = ".ai_cache"


def cache_key(provider_name: str, model: str, prompt: str) -> str:
    """Return a stable content-addressed key for one request."""
    digest = hashlib.sha256()
    digest.update(provider_name.encode("utf-8"))
    digest.update(b"\x00")
    digest.update((model or "").encode("utf-8"))
    digest.update(b"\x00")
    digest.update(prompt.encode("utf-8"))
    return digest.hexdigest()


class ResponseCache:
    """A small on-disk cache of raw model responses.

    Deliberately plain files rather than a database: the cache is an
    optimisation, so a corrupt or missing entry must degrade to a miss and
    never take the audit down with it.
    """

    def __init__(self, directory=None, enabled=True):
        self.directory = Path(directory or _DEFAULT_DIR)
        self.enabled = enabled
        self.hits = 0
        self.misses = 0

    def _path(self, key):
        return self.directory / f"{key}.json"

    def get(self, key):
        if not self.enabled:
            self.misses += 1
            return None
        path = self._path(key)
        if not path.exists():
            self.misses += 1
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            response = payload["response"]
        except (OSError, ValueError, KeyError):
            # A damaged entry is a miss, never an error.
            self.misses += 1
            return None
        self.hits += 1
        return response

    def set(self, key, response, provider_name="", model=""):
        if not self.enabled:
            return
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            payload = {
                "provider": provider_name,
                "model": model,
                "response": response,
            }
            self._path(key).write_text(
                json.dumps(payload, indent=2), encoding="utf-8"
            )
        except OSError:
            # Failing to write is not a reason to fail the audit.
            pass

    def clear(self):
        if not self.directory.exists():
            return
        for path in self.directory.glob("*.json"):
            path.unlink()

    @property
    def stats(self):
        return {"hits": self.hits, "misses": self.misses}


class CachingProvider(Provider):
    """Wraps any Provider and serves repeat prompts from disk."""

    def __init__(self, inner, cache=None):
        self.inner = inner
        self.cache = cache if cache is not None else ResponseCache()
        self.name = f"{inner.name}+cache"

    @property
    def model(self):
        return getattr(self.inner, "model", "")

    def generate(self, prompt: str) -> str:
        key = cache_key(self.inner.name, self.model, prompt)
        cached = self.cache.get(key)
        if cached is not None:
            return cached

        response = self.inner.generate(prompt)
        self.cache.set(key, response, self.inner.name, self.model)
        return response