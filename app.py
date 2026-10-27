"""
app.py
Main entry point for the Information Security Assignment 1 web application.
Covers: user auth, GDPR/UU PDP personal data encryption,
file vault (images, PDFs, video), multi-cipher benchmark lab (AES, DES, RC4).
"""

import os
import io
import json
import mimetypes
import time
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_file, jsonify, abort
)

from src import database, crypto_manager

app = Flask(__name__)
app.secret_key = os.urandom(32)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_FOLDER = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB

database.init_db()


# ---------- Helpers ---------- #

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def get_user_keys(user_password: str) -> dict:
    """Derive AES / DES / RC4 keys from the user password."""
    return crypto_manager.derive_keys_from_password(user_password)


# ---------- Auth routes ---------- #

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = database.authenticate_user(username, password)
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["user_pass"] = password
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
        else:
            user_id = database.create_user(username, password)
            if user_id:
                flash("Registration successful! You can now log in.", "success")
                return redirect(url_for("login"))
            else:
                flash("Username already exists. Please choose another.", "danger")

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been securely logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    files = database.get_user_files(user_id)
    has_profile = database.get_private_data(user_id) is not None
    return render_template("dashboard.html", files=files, has_profile=has_profile)


# ---------- Profile / private data ---------- #

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user_id  = session["user_id"]
    user_pass = session.get("user_pass", "fallback_key")
    keys = get_user_keys(user_pass)

    field_names = [
        "full_name", "nik_id", "birth_date", "birth_place", "gender",
        "religion", "marital_status", "home_address", "phone_number",
        "email_address", "health_info", "financial_account"
    ]

    if request.method == "POST":
        cipher_algo = request.form.get("cipher_algorithm", "ALL").upper()
        if cipher_algo not in ("AES", "DES", "RC4", "ALL"):
            cipher_algo = "ALL"

        encrypted_fields = {}
        for fn in field_names:
            val = request.form.get(fn, "").strip()
            if val:
                if cipher_algo == "ALL":
                    enc_aes = crypto_manager.encrypt_string(val, "AES", keys["AES"])
                    enc_des = crypto_manager.encrypt_string(val, "DES", keys["DES"])
                    enc_rc4 = crypto_manager.encrypt_string(val, "RC4", keys["RC4"])
                    encrypted_fields[fn] = json.dumps({"AES": enc_aes, "DES": enc_des, "RC4": enc_rc4})
                else:
                    encrypted_fields[fn] = crypto_manager.encrypt_string(val, cipher_algo, keys[cipher_algo])
            else:
                encrypted_fields[fn] = ""

        database.save_private_data(user_id, cipher_algo, encrypted_fields, "")
        flash(f"Donnees chiffrees et sauvegardees avec {cipher_algo} !", "success")
        return redirect(url_for("profile"))

    # GET — retrieve and decrypt
    raw_record = database.get_private_data(user_id)
    decrypted_data  = {}
    ciphertext_data = {}
    current_cipher  = "ALL"

    if raw_record:
        current_cipher = raw_record["cipher_algorithm"]
        for fn in field_names:
            val = raw_record.get(fn)
            if not val:
                ciphertext_data[fn] = ""
                decrypted_data[fn]  = ""
                continue
            if current_cipher == "ALL":
                try:
                    multi = json.loads(val)
                    ciphertext_data[fn] = multi
                    decrypted_data[fn]  = crypto_manager.decrypt_string(multi.get("AES", ""), "AES", keys["AES"])
                except Exception:
                    ciphertext_data[fn] = val
                    decrypted_data[fn]  = crypto_manager.decrypt_string(val, "AES", keys["AES"])
            else:
                ciphertext_data[fn] = val
                decrypted_data[fn]  = crypto_manager.decrypt_string(val, current_cipher, keys.get(current_cipher, keys["AES"]))

    return render_template(
        "profile.html",
        data=decrypted_data,
        cipher_data=ciphertext_data,
        current_cipher=current_cipher,
        raw_record=raw_record
    )


# ---------- File vault ---------- #

@app.route("/files")
@login_required
def files_vault():
    user_id  = session["user_id"]
    category = request.args.get("category")
    files    = database.get_user_files(user_id, category)
    return render_template("files.html", files=files, current_category=category)


@app.route("/files/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part in upload request.", "danger")
            return redirect(request.url)

        file = request.files["file"]
        if file.filename == "":
            flash("No file selected.", "danger")
            return redirect(request.url)

        category     = request.form.get("category", "document")
        cipher_choice = request.form.get("cipher_algorithm", "AES").upper()
        chosen_algos  = ["AES", "DES", "RC4"] if cipher_choice == "ALL" else [cipher_choice]

        user_id   = session["user_id"]
        user_pass = session.get("user_pass", "fallback_key")
        keys = get_user_keys(user_pass)

        original_bytes = file.read()
        original_size  = len(original_bytes)
        filename       = file.filename
        mime_type, _   = mimetypes.guess_type(filename)
        if not mime_type:
            mime_type = "application/octet-stream"

        if original_size == 0:
            flash("Cannot upload an empty file.", "danger")
            return redirect(request.url)

        for algo in chosen_algos:
            if algo not in ("AES", "DES", "RC4"):
                algo = "AES"

            key     = keys[algo]
            payload, meta = crypto_manager.encrypt_bytes(original_bytes, algo, key)

            safe_name = f"enc_{user_id}_{int(time.time()*1000)}_{algo}_{filename}.enc"
            disk_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
            with open(disk_path, "wb") as fh:
                fh.write(payload)

            database.save_file_record(
                user_id=user_id,
                category=category,
                original_filename=filename,
                file_type=mime_type,
                original_size=original_size,
                cipher_algorithm=algo,
                storage_filename=safe_name,
                encrypted_size=meta["encrypted_size"],
                encryption_time_ms=meta["time_ms"],
                entropy=meta["entropy"],
                iv_hex=meta["iv_hex"]
            )

        flash(f"File '{filename}' encrypted with {', '.join(chosen_algos)} and stored!", "success")
        return redirect(url_for("files_vault", category=category))

    return render_template("upload.html")


@app.route("/files/download/<int:file_id>")
@login_required
def download_file(file_id):
    user_id     = session["user_id"]
    file_record = database.get_file_record(file_id, user_id)
    if not file_record:
        abort(404)

    disk_path = os.path.join(app.config["UPLOAD_FOLDER"], file_record["storage_filename"])
    if not os.path.exists(disk_path):
        flash("Encrypted file not found on disk.", "danger")
        return redirect(url_for("files_vault"))

    with open(disk_path, "rb") as fh:
        payload = fh.read()

    user_pass = session.get("user_pass", "fallback_key")
    keys = get_user_keys(user_pass)
    algo = file_record["cipher_algorithm"]
    key  = keys.get(algo, keys["AES"])

    try:
        decrypted_bytes, _ = crypto_manager.decrypt_bytes(payload, algo, key)
        return send_file(
            io.BytesIO(decrypted_bytes),
            as_attachment=True,
            download_name=file_record["original_filename"],
            mimetype=file_record["file_type"]
        )
    except Exception as exc:
        flash(f"Decryption failed: {exc}", "danger")
        return redirect(url_for("files_vault"))


@app.route("/files/preview/<int:file_id>")
@login_required
def preview_file(file_id):
    user_id     = session["user_id"]
    file_record = database.get_file_record(file_id, user_id)
    if not file_record:
        abort(404)

    disk_path = os.path.join(app.config["UPLOAD_FOLDER"], file_record["storage_filename"])
    if not os.path.exists(disk_path):
        abort(404)

    with open(disk_path, "rb") as fh:
        payload = fh.read()

    user_pass = session.get("user_pass", "fallback_key")
    keys = get_user_keys(user_pass)
    algo = file_record["cipher_algorithm"]
    key  = keys.get(algo, keys["AES"])

    try:
        decrypted_bytes, _ = crypto_manager.decrypt_bytes(payload, algo, key)
        return send_file(io.BytesIO(decrypted_bytes), mimetype=file_record["file_type"], as_attachment=False)
    except Exception as exc:
        flash(f"Could not preview file: {exc}", "danger")
        return redirect(url_for("files_vault"))


@app.route("/files/raw/<int:file_id>")
@login_required
def download_raw_encrypted(file_id):
    """Download the raw encrypted ciphertext blob as stored on disk."""
    user_id     = session["user_id"]
    file_record = database.get_file_record(file_id, user_id)
    if not file_record:
        abort(404)

    disk_path = os.path.join(app.config["UPLOAD_FOLDER"], file_record["storage_filename"])
    if not os.path.exists(disk_path):
        abort(404)

    return send_file(
        disk_path,
        as_attachment=True,
        download_name=file_record["storage_filename"],
        mimetype="application/octet-stream"
    )


@app.route("/files/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    user_id          = session["user_id"]
    storage_filename = database.delete_file_record(file_id, user_id)
    if storage_filename:
        disk_path = os.path.join(app.config["UPLOAD_FOLDER"], storage_filename)
        if os.path.exists(disk_path):
            try:
                os.remove(disk_path)
            except OSError:
                pass
        flash("File successfully deleted.", "info")
    else:
        flash("File not found or permission denied.", "danger")
    return redirect(url_for("files_vault"))


# ---------- Benchmark lab ---------- #

@app.route("/benchmark")
@login_required
def benchmark():
    user_id = session["user_id"]
    files   = database.get_user_files(user_id)
    return render_template("benchmark.html", files=files)


@app.route("/api/benchmark/run", methods=["POST"])
@login_required
def api_benchmark_run():
    """Run repeated encrypt/decrypt cycles across AES, DES, RC4 for timing analysis."""
    data       = request.get_json() or {}
    iterations = max(1, min(int(data.get("iterations", 5)), 30))
    file_id    = data.get("file_id")
    synthetic_size_kb = int(data.get("synthetic_size_kb", 0))

    target_bytes = b""
    label        = "Synthetic Data"

    if file_id:
        user_id     = session["user_id"]
        file_record = database.get_file_record(int(file_id), user_id)
        if not file_record:
            return jsonify({"error": "File not found"}), 404

        disk_path = os.path.join(app.config["UPLOAD_FOLDER"], file_record["storage_filename"])
        if not os.path.exists(disk_path):
            return jsonify({"error": "File on disk missing"}), 404

        with open(disk_path, "rb") as fh:
            payload = fh.read()

        user_pass = session.get("user_pass", "fallback_key")
        keys = get_user_keys(user_pass)
        algo = file_record["cipher_algorithm"]
        key  = keys.get(algo, keys["AES"])
        target_bytes, _ = crypto_manager.decrypt_bytes(payload, algo, key)
        label = f"File: {file_record['original_filename']}"

    elif synthetic_size_kb > 0:
        size_bytes   = synthetic_size_kb * 1024
        pattern      = b"GDPR_UU_PDP_SecurityBenchmark_AES_DES_RC4_ITS_2026_"
        target_bytes = (pattern * ((size_bytes // len(pattern)) + 1))[:size_bytes]
        label        = f"Synthetic Payload ({synthetic_size_kb} KB)"
    else:
        size_bytes   = 256 * 1024
        pattern      = b"InformationSecurityAssignment1_Benchmark_AES_DES_RC4_"
        target_bytes = (pattern * ((size_bytes // len(pattern)) + 1))[:size_bytes]
        label        = "Default 256 KB Payload"

    user_pass    = session.get("user_pass", "default_pass")
    bench_results = crypto_manager.run_benchmark_on_data(target_bytes, user_pass, iterations=iterations)
    bench_results["label"] = label

    database.record_benchmark(session["user_id"], label, len(target_bytes), iterations, bench_results["ciphers"])
    return jsonify(bench_results)


# ---------- Report viewer ---------- #

@app.route("/report")
@login_required
def view_report():
    report_path = os.path.join(BASE_DIR, "REPORT.md")
    report_content = ""
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as fh:
            report_content = fh.read()
    return render_template("report.html", report_content=report_content)


if __name__ == "__main__":
    print("Starting Secure Cryptographic Vault on http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=True)
