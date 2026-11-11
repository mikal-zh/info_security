# PROJECT, 2026
# info_security
# File description:
# Start the onboarding vault on http://127.0.0.1:5000.

"""Start the onboarding vault on http://127.0.0.1:5000 (dev server)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from hrvault import create_app  # noqa: E402


def main():
    """Run the development server on the loopback interface."""
    create_app().run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
