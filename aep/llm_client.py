"""Optional LLM backend over an OpenAI-compatible chat-completions endpoint.

Uses only the standard library (``urllib``). It is configured by environment
variables and is never required: the default narrator backend is deterministic
and offline, so every test and demo runs with no network and no key.

Environment variables:

* ``AISEC_LLM_URL``   - full chat-completions URL (e.g.
  ``http://127.0.0.1:8765/v1/chat/completions``).
* ``AISEC_LLM_KEY``   - bearer token (sent as ``Authorization: Bearer ...``).
* ``AISEC_LLM_MODEL`` - model name (default ``gpt-4o-mini``).
"""

from __future__ import annotations

import json
import os
import urllib.request


class LLMNotConfigured(RuntimeError):
    """Raised when the LLM backend is requested but no URL is configured."""


class LLMClient:
    """Thin OpenAI-compatible chat-completions client."""

    def __init__(self, url: str | None = None, key: str | None = None,
                 model: str | None = None, timeout: float = 30.0) -> None:
        self.url = url or os.environ.get("AISEC_LLM_URL", "")
        self.key = key or os.environ.get("AISEC_LLM_KEY", "")
        self.model = model or os.environ.get("AISEC_LLM_MODEL", "gpt-4o-mini")
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.url)

    def chat(self, system: str, user: str, *, temperature: float = 0.0) -> str:
        """Send a two-message chat and return the assistant content string."""
        if not self.configured:
            raise LLMNotConfigured(
                "AISEC_LLM_URL is not set; use the template backend instead.")
        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.key:
            req.add_header("Authorization", f"Bearer {self.key}")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            body = json.loads(resp.read().decode("utf-8"))
        return body["choices"][0]["message"]["content"]
