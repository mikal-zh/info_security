# PROJECT, 2026
# info_security
# File description:
# Validation of the document upload form.

"""Validation of the document upload form."""

import mimetypes
from pathlib import PurePath

from flask import request

from .. import documents
from ..catalog import CATEGORIES_BY_NAME

MAX_FILENAME_LENGTH = 200
DEFAULT_MIME = "application/octet-stream"


def _clean_filename(file) -> str:
    """The file's base name without any folder part, or "" if missing."""
    if not file or not file.filename:
        return ""
    name = PurePath(file.filename).name
    return name[:MAX_FILENAME_LENGTH]


def _mime_type(filename: str) -> str:
    """MIME type guessed from the extension, or a generic binary type."""
    guessed, _ = mimetypes.guess_type(filename)
    if guessed is None:
        return DEFAULT_MIME
    return guessed


def _type_error(category, filename: str) -> str | None:
    """Error message if the category is unknown or the extension wrong."""
    if category is None:
        return "Tell us what kind of document this is."
    extension = PurePath(filename).suffix.lower()
    if extension not in category.extensions:
        allowed = ", ".join(category.extensions)
        return (f"We can only take a {category.label.lower()} as "
                f"{allowed}.")
    return None


def read_upload():
    """Return (Upload, None) for a valid form, or (None, error message)."""
    file = request.files.get("file")
    filename = _clean_filename(file)
    if not filename:
        return None, "Pick a file first."
    category = CATEGORIES_BY_NAME.get(request.form.get("category", ""))
    error = _type_error(category, filename)
    if error:
        return None, error
    data = file.read()
    if not data:
        return None, "That file is empty. Wrong one, maybe?"
    new_doc = documents.Upload(category.name, filename, _mime_type(filename),
                               data)
    return new_doc, None
