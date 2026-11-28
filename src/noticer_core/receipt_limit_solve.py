"""Return a certified release value or visibly withhold the conclusion."""

from dataclasses import dataclass
from fractions import Fraction
from typing import Literal

from noticer_core.receipt_limit_classes import trace_classes
from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_enumerate import MAX_STEPS, ReceiptCutoff
from noticer_core.receipt_limit_observer import Observer, check_observer
from noticer_core.receipt_limit_relax import construct_laws
from noticer_core.receipt_limit_verify import ReceiptCertificate, verify_receipt_certificate


@dataclass(frozen=True)
class ReceiptResult:
    """Do not expose any proof when exploration or verification was incomplete."""

    status: Literal["verified", "invalid", "inconclusive", "rejected"]
    certificate: ReceiptCertificate | None = None


def solve_receipts(
    problem: ReceiptProblem,
    observer: Observer,
    delta: Fraction,
    *,
    max_steps: int = MAX_STEPS,
    check_steps: int = MAX_STEPS,
) -> ReceiptResult:
    """Search and independently verify with separate finite budgets."""
    try:
        check_observer(problem, observer)
        if type(delta) is not Fraction or not 0 <= delta <= 1:
            raise ValueError("invalid variation budget")
        left = trace_classes(problem, observer, 0, max_steps)
        right = trace_classes(problem, observer, 1, max_steps)
        value, laws = construct_laws(left, right, delta)
        cert = ReceiptCertificate(delta, value, laws)
        valid = verify_receipt_certificate(problem, observer, cert, check_steps)
    except ValueError:
        return ReceiptResult("invalid")
    except ReceiptCutoff:
        return ReceiptResult("inconclusive")
    return ReceiptResult("verified", cert) if valid else ReceiptResult("rejected")
