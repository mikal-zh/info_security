# PROJECT, 2026
# info_security
# File description:
# The logged-in employee whose data a storage call acts on.

"""The logged-in employee whose data a storage call acts on."""

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .crypto import VaultKeys


@dataclass(frozen=True)
class Owner:
    """Database, blob folder, user id and unwrapped keys of one user.

    Every storage function takes an Owner, so ownership is always part
    of the call: a user can only ever read or change their own rows.
    """

    conn: sqlite3.Connection
    blob_dir: Path
    user_id: int
    keys: VaultKeys

    def context(self, item: str) -> str:
        """Context string binding an envelope to this user and item."""
        return f"user:{self.user_id}|{item}"
