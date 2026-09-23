"""Provider abstraction for the AI review layer.

Backends differ (a hosted model behind an API key, a model running locally),
but the review layer only needs one thing from any of them: turn a prompt
into text. This module defines that contract and the shared HTTP helper the
concrete backends use, so swapping backends is a config change, not a code
change.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from abc import ABC, abstractmethod


class ProviderError(RuntimeError):
    """Raised when a provider cannot return a usable response.

    Concrete backends wrap their own failures (network, HTTP status, bad
    payload) in this type so callers never depend on a backend's internals.
    """


class Provider(ABC):
    """A text-generation backend.

    One method, generate, by design. The narrower the interface, the easier
    it is to add a backend and the harder it is for a backend's quirks to
    leak into the rest of the system.
    """

    name: str = "provider"

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Return the model's raw text response for a single prompt."""
        raise NotImplementedError


def http_post_json(url, payload, headers=None, timeout=30):
    """POST a JSON payload and return the decoded JSON response.

    Every network and decode failure becomes a ProviderError, so the
    concrete backends can build requests and read fields without repeating
    error handling.
    """
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8")
        except Exception:
            pass
        raise ProviderError(f"HTTP {exc.code} from {url}: {detail[:200]}") from exc
    except urllib.error.URLError as exc:
        raise ProviderError(f"could not reach {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise ProviderError(f"request to {url} timed out") from exc

    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise ProviderError(
            f"response from {url} was not valid JSON: {exc}"
        ) from exc
