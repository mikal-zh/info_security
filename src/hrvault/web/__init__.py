# PROJECT, 2026
# info_security
# File description:
# Web layer: importing the view modules registers them on the blueprint.

"""Web layer: importing the view modules registers them on the blueprint."""

from . import account, auth, documents, hooks, personal
from .blueprint import bp

__all__ = ["bp", "account", "auth", "documents", "hooks", "personal"]
