from noticer_core.recovery_log_audit import LogAudit, audit_recipient_log

A = {"slot": 0, "service": "a", "action": "notify-a"}
B = {"slot": 0, "service": "b", "action": "notify-b"}


def test_audit_preserves_exact_trace_differences() -> None:
    assert audit_recipient_log([A, B], [A, B]) is LogAudit.MATCH
    assert audit_recipient_log([A, B], [B, A]) is LogAudit.REORDERED
    assert audit_recipient_log([A, B], [A]) is LogAudit.MISSING
    assert audit_recipient_log([A], [A, A]) is LogAudit.EXTRA
    assert audit_recipient_log([A], [B]) is LogAudit.DIVERGED


def test_private_or_invalid_fields_cannot_disappear_from_the_audit() -> None:
    assert audit_recipient_log([A], [A | {"debug": "not public"}]) is LogAudit.INVALID
    assert audit_recipient_log([A], [A | {"slot": True}]) is LogAudit.INVALID
