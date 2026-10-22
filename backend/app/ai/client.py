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

    def _options(self) -> dict:
        return {
            "temperature": 0,
            "num_predict": settings.ollama_num_predict,
            "num_ctx": settings.ollama_num_ctx,
        }

    def complete_json(self, prompt: str) -> str:
        try:
            response = httpx.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "format": "json",
                    "stream": False,
                    "keep_alive": settings.ollama_keep_alive,
                    "options": self._options(),
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


def warm_up(provider: str) -> None:
    """Best-effort: ask Ollama to load the model into memory ahead of the
    first real analyze request, so that request isn't paying model-load time
    out of its 35s budget. Failures are swallowed - the first real request
    still retries/falls back on its own if Ollama is unreachable."""
    if provider != "ollama":
        return
    client = OllamaClient()
    try:
        httpx.post(
            f"{client.base_url}/api/generate",
            json={
                "model": client.model,
                "prompt": "ready",
                "stream": False,
                "keep_alive": settings.ollama_keep_alive,
                "options": {**client._options(), "num_predict": 1},
            },
            timeout=client.timeout_seconds,
        )
    except httpx.HTTPError:
        pass


def ollama_status() -> dict:
    """For the admin System panel: is Ollama reachable, is the configured model
    pulled (/api/tags), and is it loaded in memory right now (/api/ps)."""
    client = OllamaClient()
    status = {"reachable": False, "model_installed": False, "model_loaded": False}
    try:
        tags = httpx.get(f"{client.base_url}/api/tags", timeout=2)
        tags.raise_for_status()
        status["reachable"] = True
        status["model_installed"] = any(m.get("name") == client.model for m in tags.json().get("models", []))
        ps = httpx.get(f"{client.base_url}/api/ps", timeout=2)
        ps.raise_for_status()
        status["model_loaded"] = any(m.get("name") == client.model for m in ps.json().get("models", []))
    except (httpx.HTTPError, ValueError):
        pass
    return status
