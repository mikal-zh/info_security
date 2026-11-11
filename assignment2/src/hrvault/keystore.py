# PROJECT, 2026
# info_security
# File description:
# In-memory store of unwrapped vault keys for logged-in users.

"""In-memory store of unwrapped vault keys, indexed by a session token.

The browser cookie holds only the token. Keys never reach the client or
the disk, and are discarded on logout, after idle timeout, or on server
restart.
"""

import secrets
import threading
import time

from .crypto import VaultKeys


class KeyStore:
    """Thread-safe map: session token -> (user id, keys, last seen)."""

    def __init__(self, idle_seconds: int):
        """Create an empty store that expires idle sessions."""
        self._idle = idle_seconds
        self._entries: dict[str, tuple[int, VaultKeys, float]] = {}
        self._lock = threading.Lock()

    def open_session(self, user_id: int, keys: VaultKeys) -> str:
        """Store the keys and return a new random session token."""
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._entries[token] = (user_id, keys, time.monotonic())
        return token

    def lookup(self, token: str | None) -> tuple[int, VaultKeys] | None:
        """Return (user id, keys) for a live token and refresh its timer.

        An unknown or idle-expired token returns None; an expired entry
        is removed at the same time.
        """
        if not token:
            return None
        with self._lock:
            entry = self._entries.get(token)
            if entry is None:
                return None
            user_id, keys, last_seen = entry
            now = time.monotonic()
            if now - last_seen > self._idle:
                del self._entries[token]
                return None
            self._entries[token] = (user_id, keys, now)
            return user_id, keys

    def close_session(self, token: str | None) -> None:
        """Forget the keys attached to one session token."""
        with self._lock:
            self._entries.pop(token, None)

    def close_user(self, user_id: int) -> None:
        """Forget every session of one user."""
        with self._lock:
            tokens = []
            for token, entry in self._entries.items():
                if entry[0] == user_id:
                    tokens.append(token)
            for token in tokens:
                del self._entries[token]
