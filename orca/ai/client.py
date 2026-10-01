"""Local and OpenAI-compatible model clients for advisory analysis."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Protocol

import requests


class AIProviderError(RuntimeError):
    """Raised when a configured model provider cannot return a response."""


class AIClient(Protocol):
    """Minimal provider interface used by the analyzer."""

    provider_name: str
    model: str

    def generate(self, prompt: str) -> str:
        """Generate one structured review response."""


@dataclass(frozen=True)
class OllamaClient:
    model: str
    endpoint: str = "http://127.0.0.1:11434"
    timeout: float = 180.0
    provider_name: str = "ollama"

    def generate(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1},
        }
        body = _post_json(
            f"{self.endpoint.rstrip('/')}/api/chat", payload, {}, self.timeout
        )
        content = body.get("message", {}).get("content")
        if not isinstance(content, str) or not content.strip():
            raise AIProviderError("Ollama returned no message content")
        return content


@dataclass(frozen=True)
class OpenAICompatibleClient:
    model: str
    endpoint: str
    api_key_env: str = "ORCA_AI_API_KEY"
    timeout: float = 180.0
    provider_name: str = "openai-compatible"

    def generate(self, prompt: str) -> str:
        headers = {"Content-Type": "application/json"}
        api_key = os.environ.get(self.api_key_env)
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }
        body = _post_json(
            f"{self.endpoint.rstrip('/')}/chat/completions",
            payload,
            headers,
            self.timeout,
        )
        choices = body.get("choices", [])
        if not choices or not isinstance(choices[0], dict):
            raise AIProviderError("Compatible provider returned no choices")
        message = choices[0].get("message", {})
        content = message.get("content") or message.get("reasoning")
        if not isinstance(content, str) or not content.strip():
            raise AIProviderError("Compatible provider returned no message content")
        return content


def _post_json(
    url: str,
    payload: Dict[str, Any],
    headers: Dict[str, str],
    timeout: float,
) -> Dict[str, Any]:
    try:
        with requests.Session() as session:
            response = session.post(url, json=payload, headers=headers, timeout=timeout)
            response.raise_for_status()
            body = response.json()
    except requests.RequestException as exc:
        raise AIProviderError(f"Model request failed: {exc}") from exc
    except ValueError as exc:
        raise AIProviderError("Model provider returned invalid JSON") from exc
    if not isinstance(body, dict):
        raise AIProviderError("Model provider returned an unexpected response shape")
    return body


def build_client(
    provider: str,
    model: str,
    endpoint: Optional[str] = None,
    api_key_env: str = "ORCA_AI_API_KEY",
    timeout: float = 180.0,
) -> AIClient:
    """Build a model client without persisting credentials in scan artifacts."""
    if provider == "ollama":
        return OllamaClient(
            model=model,
            endpoint=endpoint or "http://127.0.0.1:11434",
            timeout=timeout,
        )
    if provider == "openai-compatible":
        if not endpoint:
            raise ValueError(
                "--ai-endpoint is required for openai-compatible providers"
            )
        return OpenAICompatibleClient(
            model=model,
            endpoint=endpoint,
            api_key_env=api_key_env,
            timeout=timeout,
        )
    raise ValueError(f"Unsupported AI provider: {provider}")
