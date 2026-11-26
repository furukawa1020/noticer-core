import pytest

from noticer_core.shared_slot_views import PublicReceipt, TraceView, project_trace


def test_views_do_not_grant_private_reservation_to_a_service():
    trace = (PublicReceipt(0, "red", "a"), PublicReceipt(1, "blue", "b"))
    assert project_trace(trace, (2, 2), "service", receiver="red") == TraceView(trace[:1], None)
    assert project_trace(trace, (2, 2), "coalition") == TraceView(trace, None)
    assert project_trace(trace, (2, 2), "coalition", reservation_public=True).reservation == (2, 2)
    assert project_trace(trace, (2, 2), "network") == TraceView((), (2, 2))
    with pytest.raises(ValueError):
        project_trace(trace, (2, 2), "service")
