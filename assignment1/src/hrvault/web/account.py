# PROJECT, 2026
# info_security
# File description:
# Account views: password change and erasure.

"""Account views: password change and erasure."""

from flask import (flash, g, redirect, render_template, request, session,
                   url_for)

from .. import accounts, db, documents
from .blueprint import bp, current_owner, iterations, keystore


@bp.get("/account")
def account():
    """Password change and erasure forms."""
    return render_template("account.html")


@bp.post("/account/password")
def change_password():
    """Re-wrap the vault key under a new password."""
    new = request.form.get("new", "")
    if new != request.form.get("confirm", ""):
        flash("Your two new passwords don't match.", "danger")
        return redirect(url_for("web.account"))
    passwords = (request.form.get("old", ""), new)
    try:
        accounts.change_password(db.get(), g.user_id, passwords,
                                 iterations())
    except accounts.AccountError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("web.account"))
    flash("Password changed. Your documents stayed exactly as they were: "
          "we only re-locked your vault key.", "success")
    return redirect(url_for("web.account"))


@bp.post("/account/erase")
def erase():
    """Delete the account and all its data after a password check."""
    creds = accounts.Credentials(g.username, request.form.get("password", ""))
    if accounts.login(db.get(), creds, iterations()) is None:
        flash("Wrong password, so we haven't deleted anything.", "danger")
        return redirect(url_for("web.account"))
    documents.erase_user(current_owner())
    keystore().close_user(g.user_id)
    session.clear()
    flash("It's all gone: your account, your details and every copy of "
          "your files. Take care.", "info")
    return redirect(url_for("web.login"))
