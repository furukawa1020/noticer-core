import pytest

from noticer_core.recovery_log_binding import bind_recovery_log, verify_recovery_log


def test_matching_receipt_bytes_do_not_authorize_changed_controller_or_input() -> None:
    inputs = (b"machine-a", b"model-a", b"fault-path-a", b"[]")
    receipt = bind_recovery_log(*inputs)
    verify_recovery_log(receipt.digest, *inputs)
    for index in range(len(inputs)):
        updated = list(inputs)
        updated[index] += b"x"
        with pytest.raises(ValueError, match="substituted"):
            verify_recovery_log(receipt.digest, *updated)
