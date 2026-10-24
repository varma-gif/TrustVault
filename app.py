"""
TrustVault - a small web app for sharing documents safely.

THE BIG IDEA (say this to HR in one sentence):
    "Every time someone touches a document, the SERVER checks the database to see
     if they are allowed, and writes what happened into a log that can't be quietly changed."

HOW THIS FILE IS ORGANISED (top to bottom):
    1. Setup ............ create the app, database, login system
    2. Audit log ........ write down who did what
    3. Permission check . ONE function that decides who may do what to a document
    4. Upload checks .... make sure uploaded files are really what they say
    5. Pages (routes) ... login, dashboard, upload, download, edit, share, delete, admin
    6. Commands ......... create an admin, add demo data
"""
import hashlib
import io
import os
import secrets
import threading
import time
import zipfile
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, redirect, render_template, request,
    send_from_directory, session, url_for
)
from flask_login import (
    LoginManager, current_user, login_required, login_user, logout_user
)
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import or_, text
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from models import (
    AUDIT_TRIGGERS, GENESIS_HASH, AuditEvent, Document, DocumentPermission,
    User, db, utc_now,
)

# =============================================================================
# 1. SETUP
# =============================================================================

BASE_DIR = Path(__file__).resolve().parent

# Only these file types can be uploaded.
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt", "png", "jpg", "jpeg", "xlsx", "csv"}

# What we tell the browser each file type is when downloading.
MIME_BY_EXT = {
    "pdf": "application/pdf",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "txt": "text/plain",
    "csv": "text/csv",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
}

MAX_FILE_SIZE = 10 * 1024 * 1024        # 10 MB per file
MAX_ZIP_ENTRIES = 2000                   # docx/xlsx are zip files; stop "zip bombs"
MAX_ZIP_UNCOMPRESSED = 100 * 1024 * 1024
LOGIN_MAX_FAILURES = 5                   # wrong passwords allowed...
LOGIN_WINDOW_SECONDS = 15 * 60           # ...within this many seconds

app = Flask(__name__, instance_relative_config=True)
os.makedirs(app.instance_path, exist_ok=True)

# The SECRET_KEY signs login cookies. If someone knew it they could fake a login.
# So in real use we REFUSE to start without one. (Local testing gets a dev key.)
_secret = os.environ.get("SECRET_KEY")
_is_dev_mode = os.environ.get("FLASK_DEBUG", "0") == "1" or os.environ.get("TRUSTVAULT_TESTING") == "1"
if not _secret:
    if _is_dev_mode:
        _secret = "dev-only-not-for-production"
    else:
        raise RuntimeError(
            "SECRET_KEY must be set. Make one with: "
            "python -c \"import secrets; print(secrets.token_hex(32))\"")

app.config.update(
    SECRET_KEY=_secret,
    SQLALCHEMY_DATABASE_URI=os.environ.get(
        "TRUSTVAULT_DB_URI", "sqlite:///" + str(Path(app.instance_path) / "trustvault.db")),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=MAX_FILE_SIZE + 64 * 1024,   # reject huge requests early
    UPLOAD_FOLDER=os.environ.get("TRUSTVAULT_UPLOAD_FOLDER", str(Path(app.instance_path) / "private_uploads")),
    SESSION_COOKIE_HTTPONLY=True,       # JavaScript can't read the login cookie
    SESSION_COOKIE_SAMESITE="Lax",      # cookie isn't sent on cross-site posts
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",   # set to 1 on https
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)

# Behind a host like Render/Railway every request arrives from the host's proxy, so the login
# limiter would see ONE address for everybody. Set TRUSTVAULT_PROXY_HOPS=1 there so Flask reads
# the real visitor address. Leave it unset locally (otherwise visitors could fake their address).
_proxy_hops = int(os.environ.get("TRUSTVAULT_PROXY_HOPS", "0") or 0)
if _proxy_hops > 0:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_proxy_hops, x_proto=_proxy_hops)

db.init_app(app)
csrf = CSRFProtect(app)                  # blocks forged form posts from other websites
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "info"

_audit_lock = threading.Lock()           # makes sure two log entries aren't written at the exact same moment
_login_failures = {}                     # remembers recent wrong passwords: (ip, username) -> [times]


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login calls this on EVERY request to find out who is logged in.

    We return None (= "nobody is logged in") when:
      - the user doesn't exist, or
      - the admin has disabled them, or
      - their session is older than their 'session_version' (admin disabled them since).
    That is how a disabled person loses access immediately.
    """
    try:
        user = db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None
    if user is None or not user.active:
        return None
    if session.get("sv") != user.session_version:
        return None
    return user


@app.after_request
def add_security_headers(response):
    """Extra browser-side protections added to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"      # browser must not guess file types
    response.headers["X-Frame-Options"] = "DENY"                # our pages can't be put inside another site's frame
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; img-src 'self' data:; "
        "frame-ancestors 'none'; form-action 'self'")
    if app.config["SESSION_COOKIE_SECURE"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if current_user.is_authenticated:
        response.headers["Cache-Control"] = "no-store"          # don't keep private pages in browser cache
    return response


# =============================================================================
# 2. AUDIT LOG  (who did what, and when)
# =============================================================================
# Each log entry stores a "fingerprint" (hash) that also covers the PREVIOUS entry's
# fingerprint - like links in a chain. If anyone edits an old entry, its fingerprint
# no longer matches and the chain check shows exactly where it was broken.

def audit(action, document_id=None, details="", actor_id=None):
    """Add one entry to the audit log. (The caller must commit afterwards.)"""
    if actor_id is None and current_user.is_authenticated:
        actor_id = current_user.id

    with _audit_lock:
        last_entry = db.session.execute(
            db.select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)
        ).scalar_one_or_none()

        now = utc_now()
        entry = AuditEvent(
            actor_id=actor_id,
            document_id=document_id,
            action=action,
            details=(details or "")[:2000],
            created_at=now,
            ts=now.isoformat(),
            prev_hash=last_entry.hash if last_entry else GENESIS_HASH,
            hash="",
        )
        entry.hash = entry.compute_hash()
        db.session.add(entry)
        db.session.flush()


def record_event(action, document_id=None, details="", actor_id=None):
    """Same as audit(), but also saves it straight away. Used for refusals."""
    audit(action, document_id, details, actor_id)
    db.session.commit()


def verify_audit_chain():
    """Re-check every log entry. Returns (is_ok, first_broken_id, how_many_checked)."""
    previous_hash = GENESIS_HASH
    count = 0
    for entry in db.session.execute(db.select(AuditEvent).order_by(AuditEvent.id)).scalars():
        count += 1
        if entry.prev_hash != previous_hash or entry.hash != entry.compute_hash():
            return False, entry.id, count
        previous_hash = entry.hash
    return True, None, count


# =============================================================================
# 3. PERMISSION CHECK  <-- THE MOST IMPORTANT PART OF THE WHOLE PROJECT
# =============================================================================
# Rule of the house: every route that touches a document calls authorize() FIRST.
# Hiding a button is not security. The server must say "no" even if someone types
# the URL by hand.

def access_level(document):
    """What can the current user do with this document?
    Returns None (nothing), 'read', 'edit', 'owner' or 'admin'."""
    if not current_user.is_authenticated:
        return None
    if current_user.role == "admin":
        return "admin"
    if document.owner_id == current_user.id:
        return "owner"
    grant = DocumentPermission.query.filter_by(
        document_id=document.id, user_id=current_user.id).first()
    return grant.permission if grant else None


# A simple ranking so we can compare levels: bigger number = more power.
LEVEL_RANK = {"read": 1, "edit": 2, "owner": 3, "admin": 3}
NEEDED_RANK = {"read": 1, "edit": 2, "manage": 3}   # "manage" = share / delete / restore


def authorize(document_id, need, action_name, include_deleted=False):
    """Decide if the current user may do `need` ('read', 'edit' or 'manage') to a document.

    Returns (document, level) if allowed. Otherwise it logs the refusal and stops with:
      404 - no access at all, or the document doesn't exist (we don't reveal which)
      403 - they can see it, but their permission is too low
    """
    doc = db.session.get(Document, document_id)

    # Case 1: no such document (or it's in the trash)
    if doc is None or (doc.deleted_at is not None and not include_deleted):
        record_event(f"{action_name}_denied", None, f"requested_document_id={document_id}; reason=not_found")
        abort(404)

    level = access_level(doc)

    # Case 2: exists, but this person has no access at all.
    # We answer 404 (same as "doesn't exist") so strangers can't discover which IDs are real.
    if level is None:
        record_event(f"{action_name}_denied", doc.id, "reason=no_access")
        abort(404)

    # Case 3: has some access, but not enough for this action
    if LEVEL_RANK[level] < NEEDED_RANK[need]:
        record_event(f"{action_name}_denied", doc.id, f"reason=insufficient_access; has={level}; needs={need}")
        abort(403)

    return doc, level


def visible_documents_query():
    """A database query that only ever returns documents the user may read.
    (We filter in the database, so other people's documents are never even loaded.)"""
    query = db.select(Document).where(Document.deleted_at.is_(None))
    if current_user.role != "admin":
        shared_with_me = db.select(DocumentPermission.document_id).where(
            DocumentPermission.user_id == current_user.id)
        query = query.where(or_(Document.owner_id == current_user.id, Document.id.in_(shared_with_me)))
    return query


def role_required(*roles):
    """Decorator: only users with one of these roles may open the page."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                record_event("role_denied", None, f"endpoint={request.endpoint}; role={current_user.role}")
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


# =============================================================================
# 4. UPLOAD CHECKS
# =============================================================================
# A file's NAME can lie ("virus.exe" renamed to "report.pdf"). So we also look at the
# first bytes of the file, which identify its real type.

def validate_content(ext, data):
    """Return an error message if the bytes don't match the claimed type, else None."""
    if not data:
        return "The file is empty."
    if ext == "pdf":
        return None if data.startswith(b"%PDF-") else "File content is not a PDF."
    if ext == "png":
        return None if data.startswith(b"\x89PNG\r\n\x1a\n") else "File content is not a PNG."
    if ext in ("jpg", "jpeg"):
        return None if data.startswith(b"\xff\xd8\xff") else "File content is not a JPEG."
    if ext == "doc":
        return None if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") else "File content is not a Word document."
    if ext in ("docx", "xlsx"):
        # These are really zip files with a known structure inside.
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                items = zf.infolist()
                if len(items) > MAX_ZIP_ENTRIES or sum(i.file_size for i in items) > MAX_ZIP_UNCOMPRESSED:
                    return "Archive is too large when unpacked."
                names = {i.filename for i in items}
                folder = "word/" if ext == "docx" else "xl/"
                if "[Content_Types].xml" not in names or not any(n.startswith(folder) for n in names):
                    return f"File content is not a valid .{ext} document."
        except zipfile.BadZipFile:
            return f"File content is not a valid .{ext} document."
        return None
    if ext in ("txt", "csv"):
        if b"\x00" in data:
            return "File content is not plain text."
        try:
            data.decode("utf-8-sig")
        except UnicodeDecodeError:
            return "Text files must be UTF-8."
        return None
    return "That file type isn't allowed."


def get_extension(filename):
    """'report.PDF' -> 'pdf'"""
    return filename.rsplit(".", 1)[1].lower() if "." in filename else ""


def read_upload(uploaded):
    """Check an uploaded file. Returns (filename, extension, bytes, error_message)."""
    if not uploaded or not uploaded.filename:
        return None, None, None, "Choose a file to upload."
    original = secure_filename(uploaded.filename)     # strips things like ../../
    ext = get_extension(original)
    if not original or ext not in ALLOWED_EXTENSIONS:
        return None, None, None, "That file type isn't allowed."
    data = uploaded.read(MAX_FILE_SIZE + 1)
    if len(data) > MAX_FILE_SIZE:
        return None, None, None, "That file is too large. Maximum size is 10 MB."
    error = validate_content(ext, data)
    if error:
        return None, None, None, error
    return original, ext, data, None


def store_file(data):
    """Save bytes under a random name. The user's filename is NEVER used on disk."""
    random_name = secrets.token_hex(24)
    (Path(app.config["UPLOAD_FOLDER"]) / random_name).write_bytes(data)
    return random_name


def remove_file(storage_name):
    (Path(app.config["UPLOAD_FOLDER"]) / storage_name).unlink(missing_ok=True)


def create_document(owner, name, category, original, ext, data):
    """Save the file + its database record + an audit entry together."""
    storage_name = store_file(data)
    try:
        doc = Document(
            name=name, category=category or None, owner_id=owner.id,
            storage_name=storage_name, original_filename=original,
            mime_type=MIME_BY_EXT[ext], size_bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest())
        db.session.add(doc)
        db.session.flush()
        audit("upload", doc.id, f"filename={original}; size={len(data)}; sha256={doc.sha256}", actor_id=owner.id)
        db.session.commit()
        return doc
    except Exception:
        db.session.rollback()
        remove_file(storage_name)      # don't leave an orphan file behind
        raise


# =============================================================================
# Friendly error pages
# =============================================================================
@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403, message="You don't have permission to do that."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, message="We couldn't find that page or document."), 404


@app.errorhandler(413)
def too_large(_e):
    return render_template("error.html", code=413, message="That file is too large. Maximum size is 10 MB."), 413


@app.errorhandler(429)
def too_many(_e):
    return render_template("error.html", code=429, message="Too many attempts. Please wait and try again."), 429


# =============================================================================
# 5a. PAGES: sign up, sign in, sign out
# =============================================================================
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Anyone can sign up, but ONLY as a viewer. Owners/admins are made by an admin.
    (The role is never read from the form, so nobody can sign themselves up as admin.)"""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or len(username) > 80:
            flash("Please enter a username of 1–80 characters.", "error")
            return render_template("register.html"), 400
        if len(password) < 8:
            flash("Use a password with at least 8 characters.", "error")
            return render_template("register.html"), 400
        if User.query.filter_by(username=username).first():
            flash("That username is already taken.", "error")
            return render_template("register.html"), 409
        user = User(username=username, password_hash=generate_password_hash(password), role="viewer")
        db.session.add(user)
        try:
            db.session.flush()
            audit("user_registered", None, "role=viewer", actor_id=user.id)
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash("Could not create the account. Please try again.", "error")
            return render_template("register.html"), 409
        flash("Account created. You can sign in now.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


def _login_key(username):
    """Wrong passwords are counted per (computer address, username)."""
    return (request.remote_addr or "?", username.lower())


def _too_many_failures(key):
    now = time.time()
    recent = [t for t in _login_failures.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
    _login_failures[key] = recent
    return len(recent) >= LOGIN_MAX_FAILURES


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        key = _login_key(username)

        # Too many wrong passwords recently? Stop guessing attacks.
        if _too_many_failures(key):
            record_event("login_rate_limited", None, f"username_attempt={username[:80]}")
            abort(429)

        user = User.query.filter_by(username=username).first()
        # We check a password hash even when the user doesn't exist, so the response
        # takes the same time and doesn't reveal which usernames are real.
        password_ok = check_password_hash(
            user.password_hash if user else generate_password_hash("x"), password)

        if user and password_ok and user.active:
            _login_failures.pop(key, None)
            session.clear()
            login_user(user)
            session["sv"] = user.session_version      # remember which "session generation" this is
            session.permanent = True
            record_event("login_success", None, "User signed in.", actor_id=user.id)
            return redirect(url_for("dashboard"))

        _login_failures.setdefault(key, []).append(time.time())
        reason = "disabled_account" if (user and password_ok and not user.active) else "bad_credentials"
        record_event("login_denied", None, f"username_attempt={username[:80]}; reason={reason}",
                     actor_id=user.id if user else None)
        flash("Username or password wasn't correct.", "error")   # same message either way
        return render_template("login.html"), 401
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    record_event("logout", None, "User signed out.")
    logout_user()
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("home"))


# =============================================================================
# 5b. PAGES: documents
# =============================================================================
def _parse_date(value):
    """'2026-10-22' -> a date, or None if it isn't a valid date."""
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


@app.route("/dashboard")
@login_required
def dashboard():
    """Workspace page: lists documents + search by name, owner, category and date."""
    search_text = request.args.get("q", "").strip()[:200]
    category = request.args.get("category", "").strip()[:100]
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    # Start from "only what I'm allowed to see", THEN apply the search filters.
    allowed = visible_documents_query()
    query = allowed.join(User, Document.owner_id == User.id)

    if search_text:
        query = query.where(or_(
            Document.name.icontains(search_text, autoescape=True),
            User.username.icontains(search_text, autoescape=True)))
    if category:
        query = query.where(Document.category == category)
    start, end = _parse_date(date_from), _parse_date(date_to)
    if start:
        query = query.where(Document.created_at >= start)
    if end:
        query = query.where(Document.created_at < end + timedelta(days=1))

    documents = db.session.execute(query.order_by(Document.created_at.desc())).scalars().all()
    levels = {d.id: access_level(d) for d in documents}     # used to show Edit/Share/Delete buttons

    category_rows = db.session.execute(
        allowed.with_only_columns(Document.category).where(Document.category.is_not(None)).distinct()
    ).scalars().all()
    categories = sorted(c for c in category_rows if c)

    recent_events = []
    if current_user.role == "admin":
        recent_events = AuditEvent.query.order_by(AuditEvent.id.desc()).limit(20).all()

    return render_template(
        "dashboard.html", documents=documents, levels=levels, categories=categories,
        query=search_text, selected_category=category, date_from=date_from,
        date_to=date_to, recent_events=recent_events)


@app.route("/documents/upload", methods=["GET", "POST"])
@login_required
@role_required("owner", "admin")
def upload_document():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        category = request.form.get("category", "").strip()[:100]
        original, ext, data, error = read_upload(request.files.get("file"))
        if error:
            record_event("upload_rejected", None, f"reason={error}")
            flash(error, "error")
            return render_template("upload.html"), 400
        name = name or original
        if len(name) > 200:
            flash("Document name must be 200 characters or fewer.", "error")
            return render_template("upload.html"), 400
        try:
            create_document(current_user, name, category, original, ext, data)
        except Exception:
            app.logger.exception("Document upload failed")
            flash("Upload failed. Please try again.", "error")
            return render_template("upload.html"), 500
        flash("Document uploaded securely.", "success")
        return redirect(url_for("dashboard"))
    return render_template("upload.html")


@app.get("/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    # >>> THE LINE THAT PROTECTS DOWNLOADS. Remove it and anyone logged in could
    # >>> download any file by guessing the ID. (Tests will fail if it's removed.)
    doc, level = authorize(document_id, "read", "download")

    path = Path(app.config["UPLOAD_FOLDER"]) / doc.storage_name
    if not path.is_file():
        record_event("download_missing", doc.id, "Stored file missing.")
        abort(404)

    # If an admin opens a document that was NOT shared with them, flag it in the log.
    was_granted = DocumentPermission.query.filter_by(
        document_id=doc.id, user_id=current_user.id).first()
    admin_override = level == "admin" and doc.owner_id != current_user.id and not was_granted

    record_event("download", doc.id,
                 f"version={doc.version}; sha256={doc.sha256}" + ("; admin_override=1" if admin_override else ""))

    return send_from_directory(
        app.config["UPLOAD_FOLDER"], doc.storage_name, as_attachment=True,
        download_name=doc.original_filename, mimetype=doc.mime_type)


@app.route("/documents/<int:document_id>/edit", methods=["GET", "POST"])
@login_required
def edit_document(document_id):
    """Rename, re-categorise or replace the file. Needs 'edit' permission or better."""
    doc, _level = authorize(document_id, "edit", "edit")

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        category = request.form.get("category", "").strip()[:100]
        if not name or len(name) > 200:
            flash("Name must be 1–200 characters.", "error")
            return render_template("edit_document.html", document=doc), 400

        changes = []            # a plain-English list of what changed, for the audit log
        new_storage = None
        old_storage = None

        uploaded = request.files.get("file")
        if uploaded and uploaded.filename:
            original, ext, data, error = read_upload(uploaded)
            if error:
                record_event("upload_rejected", doc.id, f"reason={error}; during=edit")
                flash(error, "error")
                return render_template("edit_document.html", document=doc), 400
            old_ext = get_extension(doc.original_filename)
            same_type = ext == old_ext or {ext, old_ext} <= {"jpg", "jpeg"}
            if not same_type:
                flash("The replacement must be the same file type as the original.", "error")
                return render_template("edit_document.html", document=doc), 400
            new_storage = store_file(data)
            old_storage = doc.storage_name
            doc.storage_name = new_storage
            doc.size_bytes = len(data)
            doc.sha256 = hashlib.sha256(data).hexdigest()
            doc.version += 1
            changes.append(f"file_replaced=v{doc.version}; sha256={doc.sha256}")

        if name != doc.name:
            changes.append(f"name: {doc.name!r} -> {name!r}")
            doc.name = name
        if (category or None) != doc.category:
            changes.append(f"category: {doc.category!r} -> {category or None!r}")
            doc.category = category or None

        if not changes:
            flash("Nothing changed.", "info")
            return redirect(url_for("dashboard"))

        doc.updated_at = utc_now()
        try:
            audit("document_edit", doc.id, "; ".join(changes))
            db.session.commit()
        except Exception:
            db.session.rollback()
            if new_storage:
                remove_file(new_storage)
            app.logger.exception("Edit failed")
            flash("Could not save changes.", "error")
            return redirect(url_for("dashboard"))

        if old_storage:
            remove_file(old_storage)     # only remove the old file after the change is safely saved
        flash("Document updated.", "success")
        return redirect(url_for("dashboard"))

    return render_template("edit_document.html", document=doc)


@app.route("/documents/<int:document_id>/permissions", methods=["GET", "POST"])
@login_required
def manage_permissions(document_id):
    """Owner (or admin) shares the document with a named person as 'read' or 'edit'."""
    doc, _level = authorize(document_id, "manage", "permission_view")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        permission = request.form.get("permission", "")
        target = User.query.filter_by(username=username).first()

        if not target or not target.active or target.id == doc.owner_id or permission not in ("read", "edit"):
            flash("Choose a valid user and permission.", "error")
            return redirect(url_for("manage_permissions", document_id=doc.id))

        grant = DocumentPermission.query.filter_by(document_id=doc.id, user_id=target.id).first()
        before = grant.permission if grant else "none"
        if grant:
            grant.permission = permission
        else:
            db.session.add(DocumentPermission(document_id=doc.id, user_id=target.id, permission=permission))

        audit("permission_granted", doc.id,
              f"target_user_id={target.id}; target={target.username}; before={before}; after={permission}")
        db.session.commit()
        flash(f"Access updated for {target.username}.", "success")
        return redirect(url_for("manage_permissions", document_id=doc.id))

    grants = DocumentPermission.query.filter_by(document_id=doc.id).all()
    return render_template("permissions.html", document=doc, grants=grants)


@app.post("/documents/<int:document_id>/permissions/<int:user_id>/revoke")
@login_required
def revoke_permission(document_id, user_id):
    """Take access away. It works immediately because every request re-checks the database."""
    doc, _level = authorize(document_id, "manage", "permission_revoke")
    grant = DocumentPermission.query.filter_by(document_id=doc.id, user_id=user_id).first()
    if grant:
        before = grant.permission
        db.session.delete(grant)
        audit("permission_revoked", doc.id, f"target_user_id={user_id}; before={before}")
        db.session.commit()
        flash("Access revoked. Future requests will be denied immediately.", "success")
    else:
        flash("No active permission was found.", "info")
    return redirect(url_for("manage_permissions", document_id=doc.id))


@app.post("/documents/<int:document_id>/delete")
@login_required
def delete_document(document_id):
    """'Delete' only moves the document to the trash, so it can be restored."""
    doc, _level = authorize(document_id, "manage", "delete")
    doc.deleted_at = utc_now()
    audit("delete", doc.id, f"name={doc.name[:200]}; soft_delete=1")
    db.session.commit()
    flash("Document moved to trash. You can restore it from the Trash page.", "success")
    return redirect(url_for("dashboard"))


@app.route("/documents/trash")
@login_required
def trash():
    query = db.select(Document).where(Document.deleted_at.is_not(None))
    if current_user.role != "admin":
        query = query.where(Document.owner_id == current_user.id)
    documents = db.session.execute(query.order_by(Document.deleted_at.desc())).scalars().all()
    return render_template("trash.html", documents=documents)


@app.post("/documents/<int:document_id>/restore")
@login_required
def restore_document(document_id):
    doc, _level = authorize(document_id, "manage", "restore", include_deleted=True)
    if doc.deleted_at is None:
        return redirect(url_for("dashboard"))
    doc.deleted_at = None
    audit("restore", doc.id, f"name={doc.name[:200]}")
    db.session.commit()
    flash("Document restored.", "success")
    return redirect(url_for("dashboard"))


# =============================================================================
# 5c. PAGES: administrator only
# =============================================================================
@app.route("/admin/audit")
@login_required
@role_required("admin")
def admin_audit():
    """Audit trail with filters, 'worth noticing' alerts and the integrity check."""
    action = request.args.get("action", "").strip()[:50]
    document_id = request.args.get("document_id", "").strip()
    username = request.args.get("user", "").strip()[:80]

    query = db.select(AuditEvent)
    if action:
        query = query.where(AuditEvent.action == action)
    if document_id.isdigit():
        query = query.where(AuditEvent.document_id == int(document_id))
    if username:
        query = query.join(User, AuditEvent.actor_id == User.id).where(User.username == username)
    events = db.session.execute(query.order_by(AuditEvent.id.desc()).limit(200)).scalars().all()
    actions = db.session.execute(
        db.select(AuditEvent.action).distinct().order_by(AuditEvent.action)).scalars().all()

    # "Worth noticing" #1: people who were refused 3+ times in the last 24 hours
    since = utc_now() - timedelta(hours=24)
    recent_denials = AuditEvent.query.filter(
        AuditEvent.action.endswith("_denied", autoescape=True),
        AuditEvent.created_at >= since).all()
    denials_per_user = {}
    for event in recent_denials:
        who = event.actor.username if event.actor else "anonymous"
        denials_per_user[who] = denials_per_user.get(who, 0) + 1
    flagged = {user: n for user, n in denials_per_user.items() if n >= 3}

    # "Worth noticing" #2: admins who opened documents nobody shared with them
    overrides = AuditEvent.query.filter(
        AuditEvent.details.like("%admin_override=1%")).order_by(AuditEvent.id.desc()).limit(20).all()

    chain_ok, chain_bad_id, chain_count = verify_audit_chain()
    head_hash = db.session.execute(
        db.select(AuditEvent.hash).order_by(AuditEvent.id.desc()).limit(1)).scalar_one_or_none()
    return render_template(
        "admin_audit.html", events=events, actions=actions, sel_action=action,
        sel_doc=document_id, sel_user=username, flagged=flagged, overrides=overrides,
        chain_ok=chain_ok, chain_bad_id=chain_bad_id, chain_count=chain_count, head_hash=head_hash)


@app.route("/admin/users", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_users():
    """Admin creates accounts (viewer / owner / admin)."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "")
        if not username or len(username) > 80 or len(password) < 12 or role not in ("admin", "owner", "viewer"):
            flash("Username required, password at least 12 characters, valid role.", "error")
        elif User.query.filter_by(username=username).first():
            flash("That username already exists.", "error")
        else:
            user = User(username=username, password_hash=generate_password_hash(password), role=role)
            db.session.add(user)
            db.session.flush()
            audit("user_created", None, f"target_user_id={user.id}; username={username}; role={role}")
            db.session.commit()
            flash(f"Created {role} account for {username}.", "success")
        return redirect(url_for("admin_users"))
    users = User.query.order_by(User.username).all()
    return render_template("admin_users.html", users=users)


@app.post("/admin/users/<int:user_id>/toggle")
@login_required
@role_required("admin")
def admin_toggle_user(user_id):
    """Disable or re-enable a person. Disabling also ends all their open sessions."""
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("You can't disable your own account.", "error")
        return redirect(url_for("admin_users"))
    user.active = not user.active
    if not user.active:
        user.session_version += 1      # their old login cookies no longer match -> logged out everywhere
    audit("user_disabled" if not user.active else "user_enabled", None,
          f"target_user_id={user.id}; username={user.username}")
    db.session.commit()
    flash(f"{user.username} is now {'enabled' if user.active else 'disabled'}.", "success")
    return redirect(url_for("admin_users"))


# =============================================================================
# 6. SETUP COMMANDS
# =============================================================================
def init_database():
    """Create the tables and the 'audit log is append-only' triggers."""
    db.create_all()
    if db.engine.dialect.name == "sqlite":
        for statement in AUDIT_TRIGGERS:
            db.session.execute(text(statement))
    db.session.commit()


@app.cli.command("create-admin")
def create_admin():
    """Make a real administrator:  flask --app app create-admin"""
    import getpass
    username = input("Admin username: ").strip()
    password = getpass.getpass("Admin password (min 12 chars): ")
    if not username or len(username) > 80 or len(password) < 12:
        print("Invalid username or password length.")
        return
    if User.query.filter_by(username=username).first():
        print("That username already exists.")
        return
    user = User(username=username, password_hash=generate_password_hash(password), role="admin")
    db.session.add(user)
    db.session.flush()
    audit("admin_created", None, "Admin created via CLI.", actor_id=user.id)
    db.session.commit()
    print("Administrator created.")


@app.cli.command("seed-demo")
def seed_demo():
    """Fill the app with demo users + 2 sample documents:  flask --app app seed-demo
    DEMO ONLY - these passwords are public in the README."""
    # On the live site set DEMO_PASSWORD so the public README passwords do not work there.
    demo_pw = os.environ.get("DEMO_PASSWORD")
    accounts = {
        "admin_demo": ("admin", demo_pw or "AdminDemo#2026!"),
        "owner_demo": ("owner", demo_pw or "OwnerDemo#2026!"),
        "viewer_demo": ("viewer", demo_pw or "ViewerDemo#2026!"),
        "viewer_two": ("viewer", demo_pw or "ViewerTwo#2026!"),
    }
    users = {}
    for username, (role, password) in accounts.items():
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username, password_hash=generate_password_hash(password), role=role)
            db.session.add(user)
            db.session.flush()
            audit("user_created", None, f"seed; username={username}; role={role}", actor_id=user.id)
        users[username] = user
    db.session.commit()

    if not Document.query.first():
        shared = create_document(users["owner_demo"], "Shared salary letter", "HR",
                                 "salary.txt", "txt", b"Demo salary letter. Shared with viewer_demo only.\n")
        create_document(users["owner_demo"], "Private contract", "Contracts",
                        "contract.txt", "txt", b"Demo contract. Not shared with anyone.\n")
        db.session.add(DocumentPermission(
            document_id=shared.id, user_id=users["viewer_demo"].id, permission="read"))
        audit("permission_granted", shared.id,
              f"seed; target={users['viewer_demo'].username}; before=none; after=read",
              actor_id=users["owner_demo"].id)
        db.session.commit()
    print("Seeded. Accounts: admin_demo, owner_demo, viewer_demo, viewer_two (see README for passwords).")


with app.app_context():
    init_database()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")