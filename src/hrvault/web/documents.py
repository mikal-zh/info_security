# PROJECT, 2026
# info_security
# File description:
# Document upload, download, verification and deletion views.

"""Document upload, download, verification and deletion views."""

import io
import mimetypes
from pathlib import PurePath

from flask import (abort, flash, redirect, render_template, request,
                   send_file, url_for)

from .. import documents
from ..catalog import CATEGORIES, CATEGORIES_BY_NAME
from ..crypto import CIPHERS, IntegrityError
from .blueprint import bp, current_owner


@bp.get("/documents")
def documents_page():
    """Upload form and the list of the user's documents."""
    docs = documents.list_documents(current_owner())
    return render_template("documents.html", docs=docs,
                           categories=CATEGORIES, by_name=CATEGORIES_BY_NAME)


def _read_upload():
    """Return (Upload, None) for a valid form, or (None, error message)."""
    file = request.files.get("file")
    category = CATEGORIES_BY_NAME.get(request.form.get("category", ""))
    filename = PurePath(file.filename or "").name[:200] if file else ""
    if not filename:
        return None, "Pick a file first."
    if category is None:
        return None, "Tell us what kind of document this is."
    if PurePath(filename).suffix.lower() not in category.extensions:
        return None, (f"We can only take a {category.label.lower()} as "
                      f"{', '.join(category.extensions)}.")
    data = file.read()
    if not data:
        return None, "That file is empty. Wrong one, maybe?"
    mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return documents.Upload(category.name, filename, mime, data), None


@bp.post("/documents")
def upload():
    """Store a valid upload as three encrypted copies."""
    new_doc, error = _read_upload()
    if error:
        flash(error, "danger")
    else:
        documents.store_document(current_owner(), new_doc)
        flash(f"Got it! '{new_doc.filename}' is stored as three encrypted "
              "copies: AES, DES and RC4.", "success")
    return redirect(url_for("web.documents_page"))


def _send(doc_id: int, as_attachment: bool):
    """Send the requested cipher's copy, only if it passes verification."""
    cipher = request.args.get("cipher", "AES").upper()
    if cipher not in CIPHERS:
        abort(400)
    try:
        found = documents.read_document(current_owner(), doc_id, cipher)
    except (IntegrityError, OSError):
        flash(f"We stopped this download: the {cipher} copy has been "
              "altered since you uploaded it, so we won't hand it over. "
              "Try one of the other copies.", "danger")
        return redirect(url_for("web.documents_page"))
    if found is None:
        abort(404)
    return _file_response(*found, as_attachment)


def _file_response(meta: dict, data: bytes, as_attachment: bool):
    """Response carrying decrypted bytes, never cached by the browser."""
    resp = send_file(io.BytesIO(data), mimetype=meta["mime"],
                     as_attachment=as_attachment,
                     download_name=meta["filename"])
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@bp.route("/documents/<int:doc_id>/download")
def download(doc_id):
    """Download one copy of a document as an attachment."""
    return _send(doc_id, as_attachment=True)


@bp.route("/documents/<int:doc_id>/view")
def view(doc_id):
    """Open one copy of a document inline in the browser."""
    return _send(doc_id, as_attachment=False)


@bp.post("/documents/<int:doc_id>/verify")
def verify(doc_id):
    """Check all three copies and report each one."""
    report = documents.verify_document(current_owner(), doc_id)
    if report is None:
        abort(404)
    for cipher, (ok, detail) in report.items():
        if ok:
            flash(f"{cipher} copy is intact, byte for byte ({detail:,} "
                  "bytes on disk).", "success")
        else:
            flash(f"{cipher} copy is damaged and won't be released "
                  f"({detail}).", "danger")
    return redirect(url_for("web.documents_page"))


@bp.post("/documents/<int:doc_id>/delete")
def delete(doc_id):
    """Delete a document and its three encrypted copies."""
    if not documents.delete_document(current_owner(), doc_id):
        abort(404)
    flash("Done. The document and all three of its copies are gone.", "info")
    return redirect(url_for("web.documents_page"))
