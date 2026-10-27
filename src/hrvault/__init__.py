"""HR onboarding vault: employees store their onboarding data encrypted at rest."""

from pathlib import Path

from flask import Flask

from . import db
from .config import Config
from .keystore import KeyStore


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)

    data_dir = Path(app.config["DATA_DIR"])
    app.config.setdefault("DB_PATH", data_dir / "hrvault.db")
    app.config.setdefault("BLOB_DIR", data_dir / "blobs")
    Path(app.config["BLOB_DIR"]).mkdir(parents=True, exist_ok=True)
    db.init(app.config["DB_PATH"])

    app.extensions["keystore"] = KeyStore(app.config["SESSION_IDLE_SECONDS"])
    app.teardown_appcontext(db.close)

    from .routes import bp
    app.register_blueprint(bp)
    return app
