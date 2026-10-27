# PROJECT, 2026
# info_security
# File description:
# Request hooks: session loading, CSRF check and login requirement.

"""Request hooks run before every view, in the order defined here."""

import secrets

from flask import abort, flash, g, redirect, request, session, url_for

from ..crypto import CIPHERS
from .blueprint import PUBLIC_ENDPOINTS, bp, keystore


@bp.before_app_request
def load_session():
    """Attach the user id and unwrapped keys of a live session to `g`.

    A cookie whose token expired or was revoked is cleared.
    """
    g.user_id = g.keys = None
    entry = keystore().lookup(session.get("token"))
    if entry:
        g.user_id, g.keys = entry
        g.username = session.get("username")
    elif "token" in session:
        session.clear()


@bp.before_app_request
def check_csrf():
    """Reject any POST whose CSRF token does not match the session's."""
    if request.method != "POST":
        return
    expected = session.get("csrf")
    sent = request.form.get("csrf_token", "")
    if not expected or not secrets.compare_digest(sent, expected):
        abort(400, "Invalid or missing CSRF token.")


@bp.before_app_request
def require_login():
    """Send anonymous visitors of a private page to the login page."""
    if g.user_id is None and request.endpoint not in PUBLIC_ENDPOINTS:
        flash("You'll need to log in first.", "warning")
        return redirect(url_for("web.login"))
    return None


@bp.app_context_processor
def inject_globals():
    """Make the CSRF token and the cipher list available to templates."""
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["csrf"], "ciphers": CIPHERS}
