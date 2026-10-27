"""Start the onboarding vault on http://127.0.0.1:5000 (development server)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from hrvault import create_app  # noqa: E402

if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
