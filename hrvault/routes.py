import io
import mimetypes
import secrets
from functools import wraps
from pathlib import PurePath

from flask import (
    Blueprint, abort, current_app, flash, g, redirect, render_template,
    request, send_file, session, url_for,
)

from . import accounts, db, vault
from .catalog import CATEGORIES, CATEGORIES_BY_NAME, FIELDS, MAX_FIELD_LENGTH
from .crypto import CIPHERS, IntegrityError

bp = Blueprint("web", __name__)


def _keystore():
    return current_app.extensions["keystore"]


def _blob_dir():
    return current_app.config["BLOB_DIR"]


def _iterations():
    return current_app.config["PBKDF2_ITERATIONS"]


@bp.before_app_request
def load_session():
    g.user_id = g.keys = None
    entry = _keystore().lookup(session.get("token"))
    if entry:
        g.user_id, g.keys = entry
        g.username = session.get("username")
    elif "token" in session:
        session.clear()

    if request.method == "POST":
        expected = session.get("csrf")
        if not expected or not secrets.compare_digest(request.form.get("csrf_token", ""), expected):
            abort(400, "Invalid or missing CSRF token.")


@bp.app_context_processor
def inject_globals():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["csrf"], "ciphers": CIPHERS}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user_id is None:
            flash("You'll need to log in first.", "warning")
            return redirect(url_for("web.login"))
        return view(*args, **kwargs)
    return wrapped


# ---------- authentication ---------- #

@bp.route("/")
def index():
    return redirect(url_for("web.dashboard" if g.user_id else "web.login"))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if password != request.form.get("confirm", ""):
            flash("Those two passwords don't match. Try once more?", "danger")
        else:
            try:
                accounts.register(db.get(), username, password, _iterations())
                flash("You're in! Log in with your new password and let's get your file started.", "success")
                return redirect(url_for("web.login"))
            except accounts.AccountError as exc:
                flash(str(exc), "danger")
    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        result = accounts.login(db.get(), username, request.form.get("password", ""), _iterations())
        if result is None:
            flash("That employee number and password don't match. Your number is on your offer letter.", "danger")
        else:
            user_id, keys = result
            session.clear()  # new session id on privilege change
            session["token"] = _keystore().open_session(user_id, keys)
            session["username"] = username
            return redirect(url_for("web.dashboard"))
    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
def logout():
    _keystore().close_session(session.get("token"))
    session.clear()
    flash("See you soon. We've wiped your keys from the server's memory.", "info")
    return redirect(url_for("web.login"))


# ---------- dashboard & personal data ---------- #

@bp.route("/dashboard")
@login_required
def dashboard():
    fields = vault.load_personal_data(db.get(), g.user_id, g.keys)
    docs = vault.list_documents(db.get(), g.user_id, g.keys)
    have = {d["category"] for d in docs}
    return render_template(
        "dashboard.html", fields_done=len(fields), fields_total=len(FIELDS),
        docs=docs, missing=[c for c in CATEGORIES if c.name not in have],
    )


@bp.route("/personal-data", methods=["GET", "POST"])
@login_required
def personal_data():
    if request.method == "POST":
        values = {f.name: request.form.get(f.name, "").strip()[:MAX_FIELD_LENGTH] for f in FIELDS}
        vault.save_personal_data(db.get(), g.user_id, g.keys, values)
        flash("Saved. Each detail is now locked away three times: AES, DES and RC4.", "success")
        return redirect(url_for("web.personal_data"))
    stored = vault.load_personal_data(db.get(), g.user_id, g.keys)
    groups = {}
    for f in FIELDS:
        groups.setdefault(f.group, []).append(f)
    return render_template("personal_data.html", groups=groups, stored=stored)


# ---------- documents ---------- #

@bp.route("/documents", methods=["GET", "POST"])
@login_required
def documents():
    if request.method == "POST":
        upload = request.files.get("file")
        category = CATEGORIES_BY_NAME.get(request.form.get("category", ""))
        filename = PurePath(upload.filename or "").name[:200] if upload else ""
        ext = PurePath(filename).suffix.lower()
        if not upload or not filename:
            flash("Pick a file first.", "danger")
        elif category is None:
            flash("Tell us what kind of document this is.", "danger")
        elif ext not in category.extensions:
            flash(f"We can only take a {category.label.lower()} as {', '.join(category.extensions)}.", "danger")
        else:
            data = upload.read()
            if not data:
                flash("That file is empty. Wrong one, maybe?", "danger")
            else:
                mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
                vault.store_document(db.get(), _blob_dir(), g.user_id, g.keys, category.name, filename, mime, data)
                flash(f"Got it! '{filename}' is stored as three encrypted copies: AES, DES and RC4.", "success")
        return redirect(url_for("web.documents"))
    docs = vault.list_documents(db.get(), g.user_id, g.keys)
    return render_template("documents.html", docs=docs, categories=CATEGORIES, by_name=CATEGORIES_BY_NAME)


def _send(doc_id: int, as_attachment: bool):
    cipher = request.args.get("cipher", "AES").upper()
    if cipher not in CIPHERS:
        abort(400)
    try:
        found = vault.read_document(db.get(), _blob_dir(), g.user_id, g.keys, doc_id, cipher)
    except (IntegrityError, OSError):
        flash(f"We stopped this download: the {cipher} copy has been altered since you uploaded it, so we won't hand it over. Try one of the other copies.", "danger")
        return redirect(url_for("web.documents"))
    if found is None:
        abort(404)
    meta, data = found
    resp = send_file(io.BytesIO(data), mimetype=meta["mime"], as_attachment=as_attachment,
                     download_name=meta["filename"])
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@bp.route("/documents/<int:doc_id>/download")
@login_required
def download(doc_id):
    return _send(doc_id, as_attachment=True)


@bp.route("/documents/<int:doc_id>/view")
@login_required
def view(doc_id):
    return _send(doc_id, as_attachment=False)


@bp.route("/documents/<int:doc_id>/verify", methods=["POST"])
@login_required
def verify(doc_id):
    report = vault.verify_document(db.get(), _blob_dir(), g.user_id, g.keys, doc_id)
    if report is None:
        abort(404)
    for cipher, (ok, detail) in report.items():
        if ok:
            flash(f"{cipher} copy is intact, byte for byte ({detail:,} bytes on disk).", "success")
        else:
            flash(f"{cipher} copy is damaged and won't be released ({detail}).", "danger")
    return redirect(url_for("web.documents"))


@bp.route("/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete(doc_id):
    if not vault.delete_document(db.get(), _blob_dir(), g.user_id, doc_id):
        abort(404)
    flash("Done. The document and all three of its copies are gone.", "info")
    return redirect(url_for("web.documents"))


# ---------- account ---------- #

@bp.route("/account")
@login_required
def account():
    return render_template("account.html")


@bp.route("/account/password", methods=["POST"])
@login_required
def change_password():
    new = request.form.get("new", "")
    if new != request.form.get("confirm", ""):
        flash("Your two new passwords don't match.", "danger")
    else:
        try:
            accounts.change_password(db.get(), g.user_id, request.form.get("old", ""), new, _iterations())
            flash("Password changed. Your documents stayed exactly as they were: we only re-locked your vault key.", "success")
        except accounts.AccountError as exc:
            flash(str(exc), "danger")
    return redirect(url_for("web.account"))


@bp.route("/account/erase", methods=["POST"])
@login_required
def erase():
    if accounts.login(db.get(), g.username, request.form.get("password", ""), _iterations()) is None:
        flash("Wrong password, so we haven't deleted anything.", "danger")
        return redirect(url_for("web.account"))
    vault.erase_user(db.get(), _blob_dir(), g.user_id)
    _keystore().close_user(g.user_id)
    session.clear()
    flash("It's all gone: your account, your details and every copy of your files. Take care.", "info")
    return redirect(url_for("web.login"))
