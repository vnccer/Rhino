from aasm_linux_collector.redaction import REDACTED, redact_mapping, redact_text


def test_redacts_common_secret_forms_and_truncates() -> None:
    value = (
        "curl -H 'Authorization: Bearer very.secret.token' "
        "--password hunter2 token=abc123 Cookie=session-value "
        "AKIAABCDEFGHIJKLMNOP"
    )

    cleaned, count = redact_text(value, max_length=500)

    assert count >= 5
    assert "very.secret.token" not in cleaned
    assert "hunter2" not in cleaned
    assert "abc123" not in cleaned
    assert "session-value" not in cleaned
    assert "AKIAABCDEFGHIJKLMNOP" not in cleaned
    assert REDACTED in cleaned

    truncated, _ = redact_text("x" * 100, max_length=32)
    assert len(truncated) <= 35
    assert truncated.endswith("[TRUNCATED]")


def test_redacts_sensitive_mapping_keys_recursively() -> None:
    cleaned, count = redact_mapping(
        {"headers": {"Authorization": "Bearer secret", "ok": "value"}, "token": "secret"}
    )

    assert count == 2
    assert cleaned["headers"]["Authorization"] == REDACTED
    assert cleaned["token"] == REDACTED
    assert cleaned["headers"]["ok"] == "value"
