"""In-memory store of unwrapped vault keys, indexed by an opaque session token.

The browser cookie holds only the token. Keys never reach the client or the
disk, and are discarded on logout, after idle timeout, or on server restart.
"""

import secrets
import threading
import time

from .crypto import VaultKeys


class KeyStore:
    def __init__(self, idle_seconds: int):
        self._idle = idle_seconds
        self._entries: dict[str, tuple[int, VaultKeys, float]] = {}
        self._lock = threading.Lock()

    def open_session(self, user_id: int, keys: VaultKeys) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._entries[token] = (user_id, keys, time.monotonic())
        return token

    def lookup(self, token: str | None) -> tuple[int, VaultKeys] | None:
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
        with self._lock:
            self._entries.pop(token, None)

    def close_user(self, user_id: int) -> None:
        with self._lock:
            for token in [t for t, e in self._entries.items() if e[0] == user_id]:
                del self._entries[token]
