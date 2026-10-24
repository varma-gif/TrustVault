"""
models.py - the DATABASE TABLES of TrustVault.

Think of each class below as one table in an Excel workbook:
    User                 -> who can log in, and their role
    Document             -> one row per uploaded file (name, owner, size, version...)
    DocumentPermission   -> "this person may read/edit this document"
    AuditEvent           -> the diary of everything that happened
"""
import hashlib
from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

GENESIS_HASH = "0" * 64


def utc_now():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    """A person who can log in. role is admin, owner or viewer."""
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="viewer")
    # Disabled users cannot log in and every session they already hold stops working.
    active = db.Column(db.Boolean, nullable=False, default=True)
    # Bumped whenever sessions must die (disable). Stored in the session cookie and compared on every request.
    session_version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)
    documents = db.relationship("Document", backref="owner", lazy=True)

    __table_args__ = (
        db.CheckConstraint("role IN ('admin', 'owner', 'viewer')", name="valid_user_role"),
    )

    @property
    def is_active(self):  # Flask-Login reads this
        return bool(self.active)

    def __repr__(self):
        return f"<User {self.username}>"


class Document(db.Model):
    """One uploaded file. The file itself lives on disk under a random name (storage_name);
    this row only holds the details. deleted_at set = it is in the trash."""
    __tablename__ = "documents"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100))
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    storage_name = db.Column(db.String(255), unique=True, nullable=False)
    original_filename = db.Column(db.String(255), nullable=False, default="document")
    mime_type = db.Column(db.String(100), nullable=False, default="application/octet-stream")
    size_bytes = db.Column(db.Integer, nullable=False, default=0)
    sha256 = db.Column(db.String(64), nullable=False, default="")
    version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)  # soft delete
    permissions = db.relationship("DocumentPermission", backref="document", cascade="all, delete-orphan", lazy=True)


class DocumentPermission(db.Model):
    """One grant: user X may do `permission` (read or edit) on document Y.
    Deleting this row is what 'revoke' means - and it takes effect immediately."""
    __tablename__ = "document_permissions"
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("documents.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    permission = db.Column(db.String(10), nullable=False)
    user = db.relationship("User", foreign_keys=[user_id], lazy=True)

    __table_args__ = (
        db.UniqueConstraint("document_id", "user_id", name="unique_document_user_permission"),
        db.CheckConstraint("permission IN ('read', 'edit')", name="valid_document_permission"),
    )


class AuditEvent(db.Model):
    """The audit diary. Entries are only ever ADDED, never changed.
    Each entry's `hash` is a fingerprint of its content + the previous entry's hash,
    so editing an old entry breaks the chain and is detected."""
    __tablename__ = "audit_events"
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    document_id = db.Column(db.Integer, nullable=True, index=True)  # no FK: history outlives documents
    action = db.Column(db.String(50), nullable=False, index=True)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    ts = db.Column(db.String(40), nullable=False)          # exact timestamp string that was hashed
    prev_hash = db.Column(db.String(64), nullable=False, unique=True)
    hash = db.Column(db.String(64), nullable=False)
    actor = db.relationship("User", foreign_keys=[actor_id], lazy=True)

    def compute_hash(self):
        parts = [self.prev_hash, self.ts, str(self.actor_id or ""), str(self.document_id or ""),
                 self.action or "", self.details or ""]
        return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


# Database rules ("triggers"): the database itself refuses to change or delete diary entries.
AUDIT_TRIGGERS = [
    """CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
       BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;""",
    """CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
       BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;""",
]
