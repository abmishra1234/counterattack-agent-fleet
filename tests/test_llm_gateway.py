import gzip
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest

from counterstrike import llm


@pytest.mark.parametrize("status", [200, 429])
def test_gateway_handles_compressed_provider_responses(monkeypatch, status):
    payload = (
        {"choices": [{"message": {"content": "summary"}}], "usage": {"total_tokens": 3}}
        if status == 200
        else {"error": {"message": "Rate limited"}}
    )
    compressed = gzip.compress(json.dumps(payload).encode())

    def handle(request):
        return httpx.Response(
            status,
            headers={"content-encoding": "gzip", "content-length": str(len(compressed))},
            stream=httpx.ByteStream(compressed),
        )

    original_client = httpx.Client
    monkeypatch.setattr(
        llm.httpx,
        "Client",
        lambda **kwargs: original_client(transport=httpx.MockTransport(handle), **kwargs),
    )
    gateway = llm.GatewayLLM.__new__(llm.GatewayLLM)
    gateway.settings = SimpleNamespace(
        llm_provider="openai_compatible",
        llm_model="test-model",
        llm_max_output_tokens=100,
        llm_base_url="https://provider.example/v1",
        llm_api_key=SimpleNamespace(get_secret_value=lambda: "test-key"),
        llm_max_retries=0,
        llm_timeout_seconds=5,
        llm_max_response_bytes=4096,
    )
    gateway.run_id = "test-run"
    gateway.request_id = None
    gateway.actor_id = None
    gateway.job_id = None
    gateway._session_factory = MagicMock()
    gateway._persist_success = MagicMock()
    gateway._persist_failure = MagicMock()
    monkeypatch.setattr(llm, "prepare_attempt", lambda *args, **kwargs: SimpleNamespace(id="call"))

    if status == 200:
        assert gateway.complete("summarise", "system", "user", {}) == "summary"
        saved = gateway._persist_success.call_args.kwargs
        assert json.loads(saved["raw_response"]) == payload
        gateway._persist_failure.assert_not_called()
    else:
        with pytest.raises(RuntimeError, match="provider_rate_limited"):
            gateway.complete("summarise", "system", "user", {})
        saved = gateway._persist_failure.call_args.kwargs
        assert saved["error_code"] == "provider_rate_limited"
        assert saved["response_status"] == 429
