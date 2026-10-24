"""Small helper functions that make the tests easy to read."""
import io
import zipfile

from werkzeug.security import generate_password_hash

import app as app_module
from models import AuditEvent, Document, DocumentPermission, User, db

PASSWORD = "Password#12345"


def add_user(username, role="viewer", password=PASSWORD, active=True):
    with app_module.app.app_context():
        user = User(username=username, password_hash=generate_password_hash(password),
                    role=role, active=active)
        db.session.add(user)
        db.session.commit()
        return user.id


def add_doc(owner_id, name="Secret plan", category="HR", content=b"top secret words\n",
            filename="plan.txt", ext="txt"):
    with app_module.app.app_context():
        owner = db.session.get(User, owner_id)
        doc = app_module.create_document(owner, name, category, filename, ext, content)
        return doc.id


def grant(doc_id, user_id, permission="read"):
    with app_module.app.app_context():
        db.session.add(DocumentPermission(document_id=doc_id, user_id=user_id, permission=permission))
        db.session.commit()


def login(client, username, password=PASSWORD):
    return client.post("/login", data={"username": username, "password": password})


def logged_in(make_client, username):
    client = make_client()
    response = login(client, username)
    assert response.status_code == 302, f"login failed for {username}"
    return client


def get_doc(doc_id):
    """Return a plain dict describing the document right now (or None)."""
    with app_module.app.app_context():
        doc = db.session.get(Document, doc_id)
        if doc is None:
            return None
        return {"name": doc.name, "category": doc.category, "deleted": doc.deleted_at is not None,
                "version": doc.version, "storage_name": doc.storage_name,
                "original_filename": doc.original_filename}


def grants_for(doc_id):
    with app_module.app.app_context():
        rows = DocumentPermission.query.filter_by(document_id=doc_id).all()
        return {r.user_id: r.permission for r in rows}


def events(action=None):
    """Audit events as simple dicts, oldest first."""
    with app_module.app.app_context():
        query = AuditEvent.query.order_by(AuditEvent.id)
        if action:
            query = query.filter_by(action=action)
        return [{"id": e.id, "action": e.action, "actor_id": e.actor_id,
                 "document_id": e.document_id, "details": e.details or ""} for e in query.all()]


def upload(client, filename, content, name="", category=""):
    return client.post("/documents/upload", data={
        "name": name, "category": category, "file": (io.BytesIO(content), filename)},
        content_type="multipart/form-data")


def fake_docx():
    """A tiny but structurally valid .docx (it is really a zip file)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document/>")
    return buffer.getvalue()
