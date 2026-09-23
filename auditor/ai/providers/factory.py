"""Provider factory.

Turns a backend name (from an argument or the AI_PROVIDER environment
variable) into a Provider instance. This is the one place that knows the set
of backends, so the CLI and the eval harness select a backend by name and
stay ignorant of how each one is built.
"""

from __future__ import annotations

import os

from auditor.ai.providers.base import Provider, ProviderError
from auditor.ai.providers.gemini import GeminiProvider
from auditor.ai.providers.ollama import OllamaProvider

_PROVIDERS = {
    "gemini": GeminiProvider,
    "ollama": OllamaProvider,
}

_DEFAULT_PROVIDER = "gemini"


def available_providers():
    return sorted(_PROVIDERS)


def get_provider(name=None, **kwargs) -> Provider:
    name = (name or os.environ.get("AI_PROVIDER") or _DEFAULT_PROVIDER).lower()
    try:
        provider_cls = _PROVIDERS[name]
    except KeyError:
        raise ProviderError(
            f"unknown provider '{name}', choose from {available_providers()}"
        ) from None
    return provider_cls(**kwargs)
