"""Pluggable LLM client. Only one provider calls a network: "ollama" (local,
free). "template" is handled entirely in triage.py without a client, since it
is a deterministic stand-in rather than an LLM call."""

import httpx

from app.config import settings


class AIProviderError(Exception):
    """Raised when a provider fails to produce a response (network error, bad status, bad payload)."""


class LLMClient:
    def complete_json(self, prompt: str) -> str:
        raise NotImplementedError


class OllamaClient(LLMClient):
    def __init__(self, base_url: str | None = None, model: str | None = None, timeout_seconds: int | None = None):
        self.base_url = (base_url or settings.ollama_base_url).rstrip("/")
        self.model = model or settings.llm_model
        self.timeout_seconds = timeout_seconds or settings.ollama_timeout_seconds

    def complete_json(self, prompt: str) -> str:
        try:
            response = httpx.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "format": "json",
                    "stream": False,
                    "options": {"temperature": 0},
                },
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise AIProviderError(f"ollama request failed: {exc}") from exc

        try:
            return response.json()["response"]
        except (KeyError, ValueError) as exc:
            raise AIProviderError(f"ollama returned an unexpected payload: {exc}") from exc


def get_client(provider: str) -> LLMClient:
    if provider == "ollama":
        return OllamaClient()
    raise ValueError(f"No network client for LLM_PROVIDER={provider!r}")
