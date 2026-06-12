"""Targeted Zen HTTP compatibility proofs for the authoritative provider client."""

from __future__ import annotations

import json
import logging
import traceback
from io import BytesIO
from urllib.error import HTTPError, URLError

import pytest

from app.config import get_settings
from app.services import ai_provider_client

SYNTHETIC_KEY = "sk-synthetic-zen-compat-primary-xxxx"
EXPECTED_UA = "PrivacyTrace-NP/1.0"
BASE_URL = "https://zen.test/v1"
MODEL = "deepseek-v4-flash-free"


def _enable_openai_compatible(monkeypatch) -> None:
    monkeypatch.setenv("AI_ASSISTANT_ENABLED", "true")
    monkeypatch.setenv("AI_PROVIDER", "openai_compatible")
    monkeypatch.setenv("AI_BASE_URL", BASE_URL)
    monkeypatch.setenv("AI_MODEL", MODEL)
    monkeypatch.setenv("AI_MODEL_CANDIDATES", "")
    monkeypatch.setenv("AI_API_KEY", SYNTHETIC_KEY)
    monkeypatch.setenv("AI_BACKUP_API_KEYS", "")
    monkeypatch.setenv("AI_TIMEOUT_SECONDS", "5")
    get_settings.cache_clear()


def _assert_no_secret_leak(*parts: object) -> None:
    blob = " ".join(str(part) for part in parts)
    assert SYNTHETIC_KEY not in blob
    assert f"Bearer {SYNTHETIC_KEY}" not in blob


class _FakeResp:
    def __init__(self, payload: dict) -> None:
        self._body = json.dumps(payload).encode("utf-8")
        self.status = 200

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *args) -> bool:
        return False


def test_z1_real_client_sends_expected_user_agent(monkeypatch, caplog, capsys):
    _enable_openai_compatible(monkeypatch)
    seen = {}

    def opener(request, timeout=5):
        seen["url"] = request.full_url
        seen["method"] = request.get_method()
        seen["ua"] = request.get_header("User-agent")
        seen["content_type"] = request.get_header("Content-type")
        auth = request.get_header("Authorization") or ""
        seen["auth_bearer"] = auth.startswith("Bearer ")
        body = json.loads(request.data.decode("utf-8"))
        seen["model"] = body.get("model")
        _assert_no_secret_leak(request.full_url)
        return _FakeResp(
            {"choices": [{"message": {"content": '{"why_this_solution":"ok"}'}}]}
        )

    monkeypatch.setattr(ai_provider_client.urllib.request, "urlopen", opener)
    caplog.set_level(logging.DEBUG)
    result = ai_provider_client.generate_remediation_suggestion({"masked": "ping"})

    assert seen["ua"] == EXPECTED_UA
    assert seen["url"] == f"{BASE_URL}/chat/completions"
    assert seen["method"] == "POST"
    assert seen["model"] == MODEL
    assert seen["auth_bearer"] is True
    assert seen["content_type"] == "application/json"
    assert result.provider == "openai_compatible"
    assert result.model == MODEL
    captured = capsys.readouterr()
    _assert_no_secret_leak(result, caplog.text, captured.out, captured.err)


@pytest.mark.parametrize("status", [401, 403])
def test_z2_provider_rejection_uses_safe_unavailable_path(monkeypatch, caplog, capsys, status):
    _enable_openai_compatible(monkeypatch)

    def opener(request, timeout=5):
        assert request.get_header("User-agent") == EXPECTED_UA
        raise HTTPError(request.full_url, status, "rejected", hdrs=None, fp=BytesIO())

    monkeypatch.setattr(ai_provider_client.urllib.request, "urlopen", opener)
    caplog.set_level(logging.DEBUG)
    with pytest.raises(ai_provider_client.AIProviderError) as caught:
        ai_provider_client.generate_remediation_suggestion({"masked": "ping"})

    exc = caught.value
    assert exc.failure_type == "provider_unavailable"
    chain = "".join(traceback.format_exception(exc))
    captured = capsys.readouterr()
    _assert_no_secret_leak(exc, chain, caplog.text, captured.out, captured.err)


def test_z3_timeout_and_network_failure_preserve_existing_paths(monkeypatch, caplog):
    _enable_openai_compatible(monkeypatch)

    def timeout_opener(request, timeout=5):
        assert request.get_header("User-agent") == EXPECTED_UA
        raise TimeoutError("timed out")

    monkeypatch.setattr(ai_provider_client.urllib.request, "urlopen", timeout_opener)
    with pytest.raises(ai_provider_client.AIProviderError) as timed:
        ai_provider_client.generate_remediation_suggestion({"masked": "ping"})
    assert timed.value.failure_type == "timeout"
    _assert_no_secret_leak(timed.value, "".join(traceback.format_exception(timed.value)), caplog.text)

    def unavailable_opener(request, timeout=5):
        raise URLError("provider down")

    monkeypatch.setattr(ai_provider_client.urllib.request, "urlopen", unavailable_opener)
    with pytest.raises(ai_provider_client.AIProviderError) as down:
        ai_provider_client.generate_remediation_suggestion({"masked": "ping"})
    assert down.value.failure_type == "provider_unavailable"
    _assert_no_secret_leak(down.value, "".join(traceback.format_exception(down.value)), caplog.text)


def test_z4_synthetic_authorization_absent_from_errors(monkeypatch, caplog, capsys):
    _enable_openai_compatible(monkeypatch)

    def opener(request, timeout=5):
        raise HTTPError(request.full_url, 401, "rejected", hdrs=None, fp=BytesIO())

    monkeypatch.setattr(ai_provider_client.urllib.request, "urlopen", opener)
    caplog.set_level(logging.DEBUG)
    with pytest.raises(ai_provider_client.AIProviderError) as caught:
        ai_provider_client.generate_remediation_suggestion({"masked": "ping"})

    assert SYNTHETIC_KEY not in str(caught.value)
    assert "Bearer " not in str(caught.value)
    captured = capsys.readouterr()
    chain = "".join(traceback.format_exception(caught.value))
    _assert_no_secret_leak(caught.value, chain, caplog.text, captured.out, captured.err)
