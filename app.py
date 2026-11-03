import os
import re
import io
import hmac
import base64
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask, abort, flash, g, redirect, render_template, request,
    send_file, session, url_for
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

load_dotenv()

ROOT = Path(__file__).resolve().parent
STORAGE = ROOT / "storage" / "encrypted"
DB_PATH = ROOT / "instance" / "secureshare.db"
STORAGE.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", ""),
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,  # 25 MiB demo limit
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)

if len(app.config["SECRET_KEY"]) < 32:
    raise RuntimeError("Set FLASK_SECRET_KEY to a random value of at least 32 characters in .env")

def load_master_key():
    raw = os.environ.get("MASTER_KEY", "")
    try:
        key = base64.urlsafe_b64decode(raw.encode())
    except Exception as exc:
        raise RuntimeError("MASTER_KEY must be a URL-safe base64-encoded 32-byte key") from exc
    if len(key) != 32:
        raise RuntimeError("MASTER_KEY must decode to exactly 32 bytes")
    return key

MASTER_KEY = load_master_key()
WRAPPER = AESGCM(MASTER_KEY)
ALLOWED_EXTENSIONS = {
    "pdf", "txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "png", "jpg", "jpeg", "gif", "zip", "csv", "md"
}

def now_utc():
    return datetime.now(timezone.utc)

def iso_now():
    return now_utc().isoformat()

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        original_name TEXT NOT NULL,
        storage_name TEXT NOT NULL UNIQUE,
        mime_type TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        wrapped_key TEXT NOT NULL,
        nonce TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
        owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token TEXT NOT NULL UNIQUE,
        password_hash TEXT,
        expires_at TEXT NOT NULL,
        allow_download INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        share_id INTEGER REFERENCES shares(id) ON DELETE SET NULL,
        file_id INTEGER REFERENCES files(id) ON DELETE SET NULL,
        event TEXT NOT NULL,
        ip_address TEXT,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);
    CREATE INDEX IF NOT EXISTS idx_shares_token ON shares(token);
    CREATE INDEX IF NOT EXISTS idx_logs_file ON access_logs(file_id);
    """)
    conn.commit()
    conn.close()

init_db()

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]

app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def protect_post_requests():
    if request.method == "POST":
        supplied = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        if not supplied or not expected or not hmac.compare_digest(supplied, expected):
            abort(400, "Invalid or missing CSRF token")

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "script-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    return response

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def current_user():
    if "user_id" not in session:
        return None
    return db().execute("SELECT id, username, email FROM users WHERE id=?",
                        (session["user_id"],)).fetchone()

@app.context_processor
def inject_user():
    return {"current_user": current_user()}

def log_event(file_id, event, share_id=None):
    db().execute(
        "INSERT INTO access_logs (share_id, file_id, event, ip_address, created_at) VALUES (?, ?, ?, ?, ?)",
        (share_id, file_id, event, request.remote_addr, iso_now())
    )
    db().commit()

def encrypt_and_store(data: bytes):
    file_key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(file_key).encrypt(nonce, data, None)
    storage_name = secrets.token_hex(24) + ".bin"
    (STORAGE / storage_name).write_bytes(ciphertext)

    key_nonce = secrets.token_bytes(12)
    wrapped = WRAPPER.encrypt(key_nonce, file_key, b"SecureShare file key v1")
    return storage_name, base64.urlsafe_b64encode(wrapped).decode(), base64.urlsafe_b64encode(key_nonce).decode(), base64.urlsafe_b64encode(nonce).decode()

def decrypt_file(file_row):
    path = STORAGE / file_row["storage_name"]
    if not path.is_file():
        raise FileNotFoundError("Encrypted file is missing")
    wrapped = base64.urlsafe_b64decode(file_row["wrapped_key"])
    key_nonce = base64.urlsafe_b64decode(file_row["nonce_key"])
    file_key = WRAPPER.decrypt(key_nonce, wrapped, b"SecureShare file key v1")
    file_nonce = base64.urlsafe_b64decode(file_row["nonce"])
    ciphertext = path.read_bytes()
    return AESGCM(file_key).decrypt(file_nonce, ciphertext, None)

# Store a separate nonce for key wrapping. Kept in the same row as the wrapped key.
# SQLite migration is safe for both fresh and previously-created demo databases.
def ensure_schema_migrations():
    conn = sqlite3.connect(DB_PATH)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(files)").fetchall()]
    if "nonce_key" not in cols:
        conn.execute("ALTER TABLE files ADD COLUMN nonce_key TEXT")
    conn.commit()
    conn.close()

ensure_schema_migrations()

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
            flash("Username must be 3–30 characters: letters, numbers, dot, underscore or hyphen.", "danger")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email address.", "danger")
        elif len(password) < 10:
            flash("Password must be at least 10 characters.", "danger")
        else:
            try:
                db().execute(
                    "INSERT INTO users (username,email,password_hash,created_at) VALUES (?,?,?,?)",
                    (username, email, generate_password_hash(password), iso_now())
                )
                db().commit()
                flash("Account created. You can now log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username or email is already registered.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identity = request.form.get("identity", "").strip().lower()
        password = request.form.get("password", "")
        user = db().execute("SELECT * FROM users WHERE lower(username)=? OR email=?",
                            (identity, identity)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash("Welcome back.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username/email or password.", "danger")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    files = db().execute("""
        SELECT f.*,
        (SELECT COUNT(*) FROM shares s WHERE s.file_id=f.id AND s.revoked=0) AS share_count,
        (SELECT COUNT(*) FROM access_logs l WHERE l.file_id=f.id AND l.event='download') AS download_count
        FROM files f WHERE f.owner_id=? ORDER BY f.created_at DESC
    """, (user["id"],)).fetchall()
    recent = db().execute("""
        SELECT l.*, f.original_name FROM access_logs l
        LEFT JOIN files f ON f.id=l.file_id
        WHERE f.owner_id=? ORDER BY l.created_at DESC LIMIT 8
    """, (user["id"],)).fetchall()
    return render_template("dashboard.html", files=files, recent=recent)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            flash("Choose a file first.", "danger")
            return redirect(url_for("upload"))
        safe_name = secure_filename(uploaded.filename)
        if not safe_name or "." not in safe_name:
            flash("Invalid filename.", "danger")
            return redirect(url_for("upload"))
        extension = safe_name.rsplit(".", 1)[1].lower()
        if extension not in ALLOWED_EXTENSIONS:
            flash("File type not allowed. Check the accepted formats.", "danger")
            return redirect(url_for("upload"))
        data = uploaded.read()
        if not data:
            flash("Empty files are not accepted.", "danger")
            return redirect(url_for("upload"))
        storage_name, wrapped_key, key_nonce, file_nonce = encrypt_and_store(data)
        try:
            db().execute("""
                INSERT INTO files
                (owner_id, original_name, storage_name, mime_type, size_bytes, wrapped_key, nonce, nonce_key, created_at)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                session["user_id"], safe_name, storage_name,
                uploaded.mimetype or "application/octet-stream", len(data),
                wrapped_key, file_nonce, key_nonce, iso_now()
            ))
            db().commit()
        except Exception:
            (STORAGE / storage_name).unlink(missing_ok=True)
            raise
        flash(f"{safe_name} was encrypted and uploaded successfully.", "success")
        return redirect(url_for("dashboard"))
    return render_template("upload.html", allowed=", ".join(sorted(ALLOWED_EXTENSIONS)))

@app.route("/file/<int:file_id>/download")
@login_required
def owner_download(file_id):
    file_row = db().execute("SELECT * FROM files WHERE id=? AND owner_id=?",
                            (file_id, session["user_id"])).fetchone()
    if not file_row:
        abort(404)
    try:
        plaintext = decrypt_file(file_row)
    except Exception:
        app.logger.exception("File decryption failed")
        abort(500, "Could not decrypt this file. Check the configured master key.")
    log_event(file_id, "owner_download")
    return send_file(io.BytesIO(plaintext), as_attachment=True,
                     download_name=file_row["original_name"],
                     mimetype="application/octet-stream")

@app.route("/file/<int:file_id>/delete", methods=["POST"])
@login_required
def delete_file(file_id):
    row = db().execute("SELECT * FROM files WHERE id=? AND owner_id=?",
                       (file_id, session["user_id"])).fetchone()
    if not row:
        abort(404)
    (STORAGE / row["storage_name"]).unlink(missing_ok=True)
    db().execute("DELETE FROM files WHERE id=? AND owner_id=?", (file_id, session["user_id"]))
    db().commit()
    flash("File and its share links were deleted.", "success")
    return redirect(url_for("dashboard"))

@app.route("/file/<int:file_id>/share", methods=["GET", "POST"])
@login_required
def create_share(file_id):
    file_row = db().execute("SELECT * FROM files WHERE id=? AND owner_id=?",
                            (file_id, session["user_id"])).fetchone()
    if not file_row:
        abort(404)
    if request.method == "POST":
        password = request.form.get("share_password", "")
        days_raw = request.form.get("expires_days", "7")
        allow_download = 1 if request.form.get("allow_download") == "on" else 0
        try:
            days = int(days_raw)
        except ValueError:
            days = 7
        if days not in (1, 3, 7, 14, 30):
            flash("Choose a supported expiration period.", "danger")
            return redirect(url_for("create_share", file_id=file_id))
        if len(password) < 10:
            flash("Set a share password of at least 10 characters.", "danger")
            return redirect(url_for("create_share", file_id=file_id))
        token = secrets.token_urlsafe(32)
        expiry = (now_utc() + timedelta(days=days)).isoformat()
        db().execute("""
            INSERT INTO shares (file_id, owner_id, token, password_hash, expires_at, allow_download, created_at)
            VALUES (?,?,?,?,?,?,?)
        """, (file_id, session["user_id"], token, generate_password_hash(password),
              expiry, allow_download, iso_now()))
        db().commit()
        share_url = url_for("shared_file", token=token, _external=True)
        flash("Share link created. Copy the link and share its password through a separate channel.", "success")
        return render_template("share_created.html", share_url=share_url, file=file_row, expires=expiry)
    return render_template("share.html", file=file_row)

@app.route("/shares")
@login_required
def shares():
    rows = db().execute("""
        SELECT s.*, f.original_name FROM shares s
        JOIN files f ON f.id=s.file_id
        WHERE s.owner_id=? ORDER BY s.created_at DESC
    """, (session["user_id"],)).fetchall()

    # Pass current UTC time to shares.html for expiry-status comparisons.
    return render_template("shares.html", shares=rows, now_iso=iso_now())

@app.route("/share/<token>", methods=["GET", "POST"])
def shared_file(token):
    share = db().execute("""
        SELECT s.*, f.original_name, f.size_bytes, f.id AS fid
        FROM shares s JOIN files f ON f.id=s.file_id WHERE s.token=?
    """, (token,)).fetchone()
    if not share or share["revoked"]:
        abort(404)
    if datetime.fromisoformat(share["expires_at"]) <= now_utc():
        log_event(share["fid"], "expired_link", share["id"])
        return render_template("share_unavailable.html", reason="This sharing link has expired."), 410

    if request.method == "POST":
        password = request.form.get("share_password", "")
        if not share["password_hash"] or not check_password_hash(share["password_hash"], password):
            log_event(share["fid"], "failed_password", share["id"])
            flash("Incorrect sharing password.", "danger")
            return render_template("shared_file.html", share=share, unlocked=False)
        session.setdefault("unlocked_shares", [])
        unlocked = session["unlocked_shares"]
        if share["id"] not in unlocked:
            unlocked.append(share["id"])
        session["unlocked_shares"] = unlocked[-30:]
        log_event(share["fid"], "link_unlocked", share["id"])
        return redirect(url_for("shared_file", token=token))

    unlocked = share["id"] in session.get("unlocked_shares", [])
    return render_template("shared_file.html", share=share, unlocked=unlocked)

@app.route("/share/<token>/download", methods=["POST"])
def shared_download(token):
    share = db().execute("""
        SELECT s.*, f.* FROM shares s JOIN files f ON f.id=s.file_id
        WHERE s.token=?
    """, (token,)).fetchone()
    if not share or share["revoked"]:
        abort(404)
    if datetime.fromisoformat(share["expires_at"]) <= now_utc():
        return render_template("share_unavailable.html", reason="This sharing link has expired."), 410
    if share["id"] not in session.get("unlocked_shares", []):
        abort(403)
    if not share["allow_download"]:
        abort(403, "The owner has disabled downloads for this link.")
    try:
        plaintext = decrypt_file(share)
    except Exception:
        app.logger.exception("Shared file decryption failed")
        abort(500, "Could not decrypt the file.")
    log_event(share["file_id"], "download", share["id"])
    return send_file(io.BytesIO(plaintext), as_attachment=True,
                     download_name=share["original_name"],
                     mimetype="application/octet-stream")

@app.route("/share/<int:share_id>/revoke", methods=["POST"])
@login_required
def revoke_share(share_id):
    cur = db().execute("UPDATE shares SET revoked=1 WHERE id=? AND owner_id=?",
                       (share_id, session["user_id"]))
    db().commit()
    if cur.rowcount == 0:
        abort(404)
    flash("Share link revoked.", "success")
    return redirect(url_for("shares"))

@app.route("/history")
@login_required
def history():
    rows = db().execute("""
        SELECT l.*, f.original_name FROM access_logs l
        LEFT JOIN files f ON f.id=l.file_id
        WHERE f.owner_id=? ORDER BY l.created_at DESC LIMIT 100
    """, (session["user_id"],)).fetchall()
    return render_template("history.html", logs=rows)

@app.errorhandler(413)
def too_large(_error):
    return render_template("error.html", code=413, message="File is too large. Maximum upload size is 25 MiB."), 413

@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=getattr(error, "description", "Bad request.")), 400

@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", code=403, message=getattr(error, "description", "Access denied.")), 403

@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="The requested page or file was not found."), 404

@app.errorhandler(410)
def gone(_error):
    return render_template("error.html", code=410, message="This resource is no longer available."), 410

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG", "0") == "1")