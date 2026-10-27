# PROJECT, 2026
# info_security
# File description:
# Registration, login and logout views.

"""Registration, login and logout views."""

from flask import (flash, g, redirect, render_template, request, session,
                   url_for)

from .. import accounts, db
from .blueprint import bp, iterations, keystore


def _form_credentials() -> accounts.Credentials:
    """Employee number and password from the submitted form."""
    return accounts.Credentials(request.form.get("username", "").strip(),
                                request.form.get("password", ""))


@bp.route("/")
def index():
    """Send visitors to their dashboard, or to the login page."""
    if g.user_id:
        return redirect(url_for("web.dashboard"))
    return redirect(url_for("web.login"))


def _try_register() -> bool:
    """Create the account from the form; flash the outcome."""
    if request.form.get("password") != request.form.get("confirm"):
        flash("Those two passwords don't match. Try once more?", "danger")
        return False
    try:
        accounts.register(db.get(), _form_credentials(), iterations())
    except accounts.AccountError as exc:
        flash(str(exc), "danger")
        return False
    flash("You're in! Log in with your new password and let's get your "
          "file started.", "success")
    return True


@bp.route("/register", methods=["GET", "POST"])
def register():
    """Show the registration form and handle its submission."""
    if request.method == "POST" and _try_register():
        return redirect(url_for("web.login"))
    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    """Check credentials, unwrap the vault key and open a session.

    The session is cleared first so the logged-in user gets a new
    session id.
    """
    if request.method != "POST":
        return render_template("login.html")
    creds = _form_credentials()
    result = accounts.login(db.get(), creds, iterations())
    if result is None:
        flash("That employee number and password don't match. Your number "
              "is on your offer letter.", "danger")
        return render_template("login.html")
    session.clear()
    session["token"] = keystore().open_session(*result)
    session["username"] = creds.username
    return redirect(url_for("web.dashboard"))


@bp.route("/logout", methods=["POST"])
def logout():
    """Drop the session's keys from memory and clear the cookie."""
    keystore().close_session(session.get("token"))
    session.clear()
    flash("See you soon. We've wiped your keys from the server's memory.",
          "info")
    return redirect(url_for("web.login"))
