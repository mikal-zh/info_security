# PROJECT, 2026
# info_security
# File description:
# Dashboard and personal-data views.

"""Dashboard and personal-data views."""

from flask import flash, redirect, render_template, request, url_for

from .. import documents, personal
from ..catalog import CATEGORIES, FIELDS, MAX_FIELD_LENGTH
from .blueprint import bp, current_owner


@bp.route("/dashboard")
def dashboard():
    """Progress of the onboarding file and the latest uploads."""
    owner = current_owner()
    fields = personal.load_personal_data(owner)
    docs = documents.list_documents(owner)
    uploaded = {doc["category"] for doc in docs}
    missing = [item for item in CATEGORIES if item.name not in uploaded]
    return render_template("dashboard.html", fields_done=len(fields),
                           fields_total=len(FIELDS), docs=docs,
                           missing=missing)


@bp.get("/personal-data")
def personal_data():
    """The personal-data form, grouped by section, with copy status."""
    stored = personal.load_personal_data(current_owner())
    groups = {}
    for item in FIELDS:
        groups.setdefault(item.group, []).append(item)
    return render_template("personal_data.html", groups=groups,
                           stored=stored)


@bp.post("/personal-data")
def save_personal_data():
    """Seal every submitted field with AES, DES and RC4."""
    values = {item.name: request.form.get(item.name, "").strip()
              [:MAX_FIELD_LENGTH] for item in FIELDS}
    personal.save_personal_data(current_owner(), values)
    flash("Saved. Each detail is now locked away three times: AES, DES "
          "and RC4.", "success")
    return redirect(url_for("web.personal_data"))
