# PROJECT, 2026
# info_security
# File description:
# Shared pytest fixtures: a fresh app and logged-in clients.

"""Shared pytest fixtures: a fresh app and logged-in clients."""

import pytest

from hrvault import create_app
from tests.helpers import register_and_login


@pytest.fixture
def app(tmp_path):
    """An app with its own data folder, fast PBKDF2 and small RSA keys."""
    return create_app({"DATA_DIR": tmp_path, "PBKDF2_ITERATIONS": 1000,
                       "RSA_KEY_BITS": 1024, "TESTING": True})


@pytest.fixture
def client(app):
    """A client logged in as employee emp-001."""
    test_client = app.test_client()
    register_and_login(test_client)
    return test_client
