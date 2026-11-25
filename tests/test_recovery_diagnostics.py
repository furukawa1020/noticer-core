import pytest

from noticer_core.recovery_diagnostics import AvailabilityClass, PublicDiagnostic, public_diagnostic


def test_public_outage_does_not_expose_internal_failure_detail() -> None:
    assert public_diagnostic(AvailabilityClass.PUBLIC_OUTAGE) is PublicDiagnostic.DEFERRED
    with pytest.raises(ValueError, match="declared public availability"):
        public_diagnostic("public-outage")  # type: ignore[arg-type]
