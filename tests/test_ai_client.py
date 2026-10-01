import pytest

from orca.ai import client as client_module
from orca.ai.client import OllamaClient, OpenAICompatibleClient, build_client


def test_builds_ollama_with_safe_local_default() -> None:
    client = build_client("ollama", "qwen3:0.6b")

    assert isinstance(client, OllamaClient)
    assert client.endpoint == "http://127.0.0.1:11434"


def test_compatible_provider_requires_endpoint() -> None:
    with pytest.raises(ValueError, match="ai-endpoint"):
        build_client("openai-compatible", "local-model")


def test_builds_compatible_client_without_copying_key_value(monkeypatch) -> None:
    monkeypatch.setenv("MY_PRIVATE_KEY", "do-not-store")

    client = build_client(
        "openai-compatible",
        "local-model",
        endpoint="http://model.test/v1",
        api_key_env="MY_PRIVATE_KEY",
    )

    assert isinstance(client, OpenAICompatibleClient)
    assert client.api_key_env == "MY_PRIVATE_KEY"
    assert "do-not-store" not in repr(client)


def test_compatible_client_accepts_reasoning_field_from_local_servers(
    monkeypatch,
) -> None:
    def fake_post_json(url, payload, headers, timeout):
        return {
            "choices": [
                {"message": {"content": None, "reasoning": '{"verdict":"likely"}'}}
            ]
        }

    monkeypatch.setattr(client_module, "_post_json", fake_post_json)
    client = OpenAICompatibleClient(
        model="local-model", endpoint="http://model.test/v1"
    )

    assert client.generate("review") == '{"verdict":"likely"}'
