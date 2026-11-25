"""Content-addressed binding for synthetic receiver replay artifacts."""

from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest


@dataclass(frozen=True, slots=True)
class RecoveryLogBinding:
    machine_sha256: str
    model_sha256: str
    replay_input_sha256: str
    received_log_sha256: str

    @property
    def digest(self) -> str:
        parts = (
            self.machine_sha256, self.model_sha256,
            self.replay_input_sha256, self.received_log_sha256,
        )
        if any(len(part) != 64 or not set(part) <= set("0123456789abcdef") for part in parts):
            raise ValueError("expected four canonical SHA-256 components")
        components = b"".join(bytes.fromhex(part) for part in parts)
        return sha256(b"K22-RECOVERY-LOG-V1\x00" + components).hexdigest()


def bind_recovery_log(
    machine: bytes, model: bytes, replay_input: bytes, received_log: bytes
) -> RecoveryLogBinding:
    """Identify the exact components. Content binding is not a signature."""
    return RecoveryLogBinding(
        sha256(machine).hexdigest(), sha256(model).hexdigest(),
        sha256(replay_input).hexdigest(), sha256(received_log).hexdigest(),
    )


def verify_recovery_log(
    expected: str, machine: bytes, model: bytes, replay_input: bytes, received_log: bytes
) -> None:
    actual = bind_recovery_log(machine, model, replay_input, received_log).digest
    if not compare_digest(expected, actual):
        raise ValueError("received log or its declared replay context was substituted")
