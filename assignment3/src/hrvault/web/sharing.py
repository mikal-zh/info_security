# PROJECT, 2026
# info_security
# File description:
# Sharing views: request access, decide on requests, read a shared file.

"""Sharing views: request access, decide on requests, read a share."""

from flask import abort, flash, g, redirect, render_template, request, url_for

from .. import db, keypairs, share_snapshot, shared_view, sharing
from ..crypto import IntegrityError
from .blueprint import bp, current_owner, share_dir
from .documents import file_response

DECISIONS = {
    "reject": ("rejected", "Request declined. Nothing was shared."),
    "revoke": ("revoked", "Access revoked: the shared copy is deleted."),
}


@bp.get("/sharing")
def sharing_page():
    """Request form, requests received and requests sent."""
    conn = db.get()
    return render_template("sharing.html",
                           incoming=sharing.incoming(conn, g.user_id),
                           outgoing=sharing.outgoing(conn, g.user_id),
                           key=keypairs.key_info(conn, g.user_id))


@bp.post("/sharing/request")
def request_access():
    """Ask another employee for access to their file."""
    username = request.form.get("username", "").strip()
    try:
        sharing.request_access(db.get(), g.user_id, username)
    except sharing.SharingError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("web.sharing_page"))
    flash(f"Request sent to {username}. You'll get access once they "
          "approve it.", "success")
    return redirect(url_for("web.sharing_page"))


@bp.post("/sharing/<int:request_id>/approve")
def approve(request_id):
    """Share a snapshot of the file, its key wrapped for the requester."""
    try:
        done = share_snapshot.approve(current_owner(), request_id,
                                      share_dir())
    except sharing.SharingError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("web.sharing_page"))
    if not done:
        abort(404)
    flash("Shared. We re-locked a copy of your file with a fresh key and "
          "sealed that key with the requester's RSA public key.", "success")
    return redirect(url_for("web.sharing_page"))


@bp.post("/sharing/<int:request_id>/<action>")
def decide(request_id, action):
    """Reject a pending request or revoke an approved share."""
    if action not in DECISIONS:
        abort(404)
    status, message = DECISIONS[action]
    if not share_snapshot.decide(current_owner(), request_id, status,
                                 share_dir()):
        abort(404)
    flash(message, "info")
    return redirect(url_for("web.sharing_page"))


def _opened_share(request_id: int):
    """The share for the current requester; 404 if they have none."""
    try:
        share = shared_view.open_share(current_owner(), request_id,
                                       share_dir())
    except IntegrityError:
        abort(409, "The shared key could not be unwrapped.")
    if share is None:
        abort(404)
    return share


@bp.get("/shared/<int:request_id>")
def shared_file(request_id):
    """The personal data and documents someone shared with you."""
    share = _opened_share(request_id)
    try:
        fields = shared_view.shared_fields(share)
        docs = shared_view.shared_documents(share)
    except IntegrityError:
        abort(409, "The shared copy failed its integrity check.")
    return render_template("shared_file.html", share=share.row,
                           fields=fields, docs=docs)


@bp.get("/shared/<int:request_id>/documents/<int:doc_id>")
def shared_download(request_id, doc_id):
    """Download a shared document after checking its integrity."""
    share = _opened_share(request_id)
    try:
        found = shared_view.read_shared_document(share, doc_id)
    except (IntegrityError, OSError):
        flash("We stopped this download: the shared copy has been "
              "altered.", "danger")
        return redirect(url_for("web.shared_file", request_id=request_id))
    if found is None:
        abort(404)
    return file_response(*found, as_attachment=True)
