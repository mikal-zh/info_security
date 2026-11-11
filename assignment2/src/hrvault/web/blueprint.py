# PROJECT, 2026
# info_security
# File description:
# The web blueprint and helpers shared by every view.

"""The web blueprint and helpers shared by every view."""

from flask import Blueprint, current_app, g

from .. import db
from ..owner import Owner

bp = Blueprint("web", __name__)

PUBLIC_ENDPOINTS = {"web.index", "web.login", "web.register", "web.logout",
                    "static", None}


def keystore():
    """The application's in-memory key store."""
    return current_app.extensions["keystore"]


def iterations() -> int:
    """PBKDF2 iteration count for new or changed passwords."""
    return current_app.config["PBKDF2_ITERATIONS"]


def rsa_bits() -> int:
    """Modulus size of newly generated RSA key pairs."""
    return current_app.config["RSA_KEY_BITS"]


def share_dir():
    """Folder holding the encrypted files of shared documents."""
    return current_app.config["SHARE_DIR"]


def owner_of(user_id: int, keys) -> Owner:
    """An Owner for this user, with the request's database connection."""
    return Owner(db.get(), current_app.config["BLOB_DIR"], user_id, keys)


def current_owner() -> Owner:
    """The logged-in employee, with the request's database connection."""
    return owner_of(g.user_id, g.keys)
