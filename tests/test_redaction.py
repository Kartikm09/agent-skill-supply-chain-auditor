"""Unit tests for secret-shape recognition and irreversible evidence handling."""

from __future__ import annotations

from skill_auditor.redaction import find_secret_matches, redact_text, secret_fingerprint


def test_redacts_assigned_secret_without_retaining_value() -> None:
    value = "synthetic-token-value-123456789"
    rendered = redact_text(f"api_key={value}")
    assert value not in rendered
    assert "<redacted-value:" in rendered


def test_environment_placeholders_are_not_reported() -> None:
    assert find_secret_matches('"token": "${RUNTIME_TOKEN}"') == []
    assert find_secret_matches("token=<SET_AT_RUNTIME>") == []


def test_secret_fingerprint_is_stable_and_one_way() -> None:
    value = "synthetic-secret-value-000000"
    assert secret_fingerprint(value) == secret_fingerprint(value)
    assert value not in secret_fingerprint(value)
    assert len(secret_fingerprint(value)) == 12


def test_redaction_caps_long_evidence() -> None:
    assert len(redact_text("x" * 500, limit=40)) == 40


def test_redacted_markers_are_idempotent() -> None:
    marker = '"ACCESS_TOKEN": "<redacted-value:2b6975c74a4a>"'
    assert find_secret_matches(marker) == []
    assert redact_text(marker) == marker


def test_url_userinfo_is_redacted() -> None:
    userinfo = "user:" + "password"
    rendered = redact_text(f"source: https://{userinfo}@example.invalid/project")
    assert userinfo not in rendered
    assert "https://<redacted-value:" in rendered
