# PROJECT, 2026
# info_security
# File description:
# Dashboard and personal-data views.

"""Dashboard and personal-data views."""

from flask import flash, redirect, render_template, request, url_for

from .. import documents, personal
from ..catalog import CATEGORIES, FIELDS, MAX_FIELD_LENGTH
from .blueprint import bp, current_owner


def _missing_categories(docs: list[dict]) -> list:
    """Document types the employee has not uploaded yet."""
    uploaded = set()
    for doc in docs:
        uploaded.add(doc["category"])
    missing = []
    for category in CATEGORIES:
        if category.name not in uploaded:
            missing.append(category)
    return missing


@bp.route("/dashboard")
def dashboard():
    """Progress of the onboarding file and the latest uploads."""
    owner = current_owner()
    fields = personal.load_personal_data(owner)
    docs = documents.list_documents(owner)
    missing = _missing_categories(docs)
    return render_template("dashboard.html", fields_done=len(fields),
                           fields_total=len(FIELDS), docs=docs,
                           missing=missing)


@bp.get("/personal-data")
def personal_data():
    """The personal-data form, grouped by section, with copy status."""
    stored = personal.load_personal_data(current_owner())
    groups = {}
    for field in FIELDS:
        if field.group not in groups:
            groups[field.group] = []
        groups[field.group].append(field)
    return render_template("personal_data.html", groups=groups,
                           stored=stored)


def _form_values() -> dict[str, str]:
    """Submitted value of every field, trimmed and length-limited."""
    values = {}
    for field in FIELDS:
        value = request.form.get(field.name, "").strip()
        values[field.name] = value[:MAX_FIELD_LENGTH]
    return values


@bp.post("/personal-data")
def save_personal_data():
    """Seal every submitted field with AES, DES and RC4."""
    values = _form_values()
    personal.save_personal_data(current_owner(), values)
    flash("Saved. Each detail is now locked away three times: AES, DES "
          "and RC4.", "success")
    return redirect(url_for("web.personal_data"))
