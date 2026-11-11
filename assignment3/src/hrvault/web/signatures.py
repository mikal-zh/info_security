# PROJECT, 2026
# info_security
# File description:
# Signature views: sign a stored PDF, check it, verify any uploaded PDF.

"""Signature views: sign a stored PDF, check it, verify any PDF."""

from flask import abort, flash, redirect, render_template, request, url_for

from .. import db, signing
from ..pdfsign.pdf_lexer import PdfError
from .blueprint import bp, current_owner, rsa_bits


def _back_to_documents():
    """Redirect to the documents page."""
    return redirect(url_for("web.documents_page"))


@bp.post("/documents/<int:doc_id>/sign")
def sign_document(doc_id):
    """Embed the owner's signature in one of their PDFs."""
    try:
        result = signing.sign_document(current_owner(), doc_id, rsa_bits())
    except signing.SigningError as exc:
        flash(str(exc), "danger")
        return _back_to_documents()
    if result is None:
        abort(404)
    if result.key_created:
        flash("You had no key pair, so we generated one first.", "info")
    flash(f"'{result.filename}' now carries your digital signature. "
          "Download it and open it in any PDF reader to see it.", "success")
    return _back_to_documents()


@bp.get("/documents/<int:doc_id>/signatures")
def document_signatures(doc_id):
    """Report on every signature of one of the user's PDFs."""
    try:
        found = signing.check_document(current_owner(), doc_id)
    except (signing.SigningError, PdfError) as exc:
        flash(str(exc), "danger")
        return _back_to_documents()
    if found is None:
        abort(404)
    meta, checks = found
    return render_template("signature_report.html",
                           filename=meta["filename"], checks=checks)


@bp.route("/signatures/verify", methods=["GET", "POST"])
def verify_any_pdf():
    """Upload any PDF and check the signatures it carries."""
    if request.method != "POST":
        return render_template("signature_report.html", checks=None)
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        flash("Pick a PDF first.", "danger")
        return redirect(url_for("web.verify_any_pdf"))
    try:
        checks = signing.check_pdf(db.get(), upload.read())
    except PdfError as exc:
        flash(f"We couldn't read that PDF ({exc}).", "danger")
        return redirect(url_for("web.verify_any_pdf"))
    return render_template("signature_report.html",
                           filename=upload.filename, checks=checks)
