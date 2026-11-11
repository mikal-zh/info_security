# PROJECT, 2026
# info_security
# File description:
# Key pair views: generate, import, download certificate and public key.

"""Key pair views: generate, import, download certificate and key."""

import io

from Crypto.PublicKey import RSA
from flask import (abort, flash, g, redirect, render_template, request,
                   send_file, url_for)

from .. import db, key_import, keypairs
from .blueprint import bp, current_owner, rsa_bits


@bp.get("/keys")
def keys_page():
    """The user's key pair, or the forms to create or import one."""
    key = keypairs.key_info(db.get(), g.user_id)
    return render_template("keys.html", key=key)


@bp.post("/keys/generate")
def generate_keys():
    """Generate a key pair and certificate if the user has none."""
    if keypairs.ensure_key_pair(current_owner(), rsa_bits()):
        flash("Your RSA key pair and certificate are ready. The private "
              "key is locked with your password.", "success")
    else:
        flash("You already have a key pair.", "warning")
    return redirect(url_for("web.keys_page"))


@bp.post("/keys/import")
def import_keys():
    """Store the user's own private key and issue a certificate for it."""
    upload = request.files.get("key_file")
    data = b""
    if upload is not None:
        data = upload.read()
    try:
        key_import.import_key_pair(current_owner(), data,
                                   request.form.get("passphrase", ""))
    except key_import.KeyImportError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("web.keys_page"))
    flash("Your key is imported and locked with your password. We issued "
          "a certificate for it.", "success")
    return redirect(url_for("web.keys_page"))


def _download(data: bytes, mimetype: str, filename: str):
    """Send public key material as a file download."""
    return send_file(io.BytesIO(data), mimetype=mimetype,
                     as_attachment=True, download_name=filename)


@bp.get("/keys/certificate.cer")
def download_certificate():
    """The user's DER certificate, to trust it in a PDF reader."""
    cert = keypairs.certificate_of(db.get(), g.user_id)
    if cert is None:
        abort(404)
    return _download(cert, "application/pkix-cert", f"{g.username}.cer")


@bp.get("/keys/public.pem")
def download_public_key():
    """The user's public key in PEM form."""
    public = keypairs.public_key_of(db.get(), g.user_id)
    if public is None:
        abort(404)
    pem = RSA.import_key(public).export_key(format="PEM")
    return _download(pem, "application/x-pem-file",
                     f"{g.username}-public.pem")
