# PROJECT, 2026
# info_security
# File description:
# Request validation: self, unknown employee and duplicate requests.

"""Request validation: self, unknown employee and duplicate requests."""

import pytest

from tests.helpers import post_form, register_and_login


@pytest.mark.parametrize("username, message", [
    ("emp-001", b"That&#39;s you"),
    ("nobody-9", b"No employee has that number"),
])
def test_invalid_requests_are_refused(client, username, message):
    """Asking for yourself or an unknown employee is refused."""
    resp = post_form(client, "/sharing/request", {"username": username},
                     follow=True)
    assert message in resp.data


def test_duplicate_request_is_refused(app, client):
    """A second open request for the same file is refused."""
    hr_client = app.test_client()
    register_and_login(hr_client, "hr-001")
    post_form(hr_client, "/sharing/request", {"username": "emp-001"})
    resp = post_form(hr_client, "/sharing/request",
                     {"username": "emp-001"}, follow=True)
    assert b"already have an open request" in resp.data


def test_new_request_allowed_after_rejection(app, client):
    """Once a request is declined, the requester may ask again."""
    hr_client = app.test_client()
    register_and_login(hr_client, "hr-001")
    post_form(hr_client, "/sharing/request", {"username": "emp-001"})
    post_form(client, "/sharing/1/reject", {})
    resp = post_form(hr_client, "/sharing/request",
                     {"username": "emp-001"}, follow=True)
    assert b"Request sent to emp-001" in resp.data
