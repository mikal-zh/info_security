# PROJECT, 2026
# info_security
# File description:
# Authentication tests: login, CSRF, session cookie and logout.

"""Authentication tests: login, CSRF, session cookie and logout."""

from flask.sessions import SecureCookieSessionInterface

from tests.helpers import PASSWORD, post_form

PRIVATE_PAGES = ["/dashboard", "/personal-data", "/documents",
                 "/documents/1/download", "/account"]


def test_pages_require_login(app):
    """Every private page redirects an anonymous visitor."""
    anonymous = app.test_client()
    for path in PRIVATE_PAGES:
        assert anonymous.get(path).status_code == 302


def test_post_without_csrf_token_is_rejected(app):
    """A form posted without the CSRF token gets a 400."""
    form = {"username": "x", "password": "y"}
    assert app.test_client().post("/login", data=form).status_code == 400


def test_wrong_password_is_refused(client):
    """A wrong password does not open a session."""
    post_form(client, "/logout", {})
    resp = post_form(client, "/login", {"username": "emp-001",
                                        "password": "wrong-password"})
    assert b"employee number and password don&#39;t match" in resp.data
    assert client.get("/documents").status_code == 302


def test_cookie_carries_no_password_or_key(app, client):
    """The signed cookie holds only a token, the name and the CSRF value."""
    serializer = SecureCookieSessionInterface().get_signing_serializer(app)
    cookie = client.get_cookie("session").value
    assert PASSWORD not in cookie
    assert set(serializer.loads(cookie)) <= {"token", "username", "csrf",
                                             "_flashes"}


def test_logout_drops_keys(client):
    """After logout the private pages are closed again."""
    post_form(client, "/logout", {})
    assert client.get("/documents").status_code == 302
