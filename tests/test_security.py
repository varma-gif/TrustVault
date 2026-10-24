"""
test_security.py - proves that one person cannot reach another person's documents,
and that the audit trail, upload checks and sessions behave.

Each test name matches a row in THREATS.md.
"""
import os
import re

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

import app as app_module
from models import AuditEvent, Document, User, db
from tests.helpers import (
    PASSWORD, add_doc, add_user, events, fake_docx, get_doc, grant, grants_for,
    logged_in, login, upload,
)


# ----------------------------------------------------------------------------
# Threat 1: guessing /documents/<id>/... (IDOR)
# ----------------------------------------------------------------------------
def test_stranger_cannot_download_edit_share_delete(make_client):
    owner = add_user("olivia", "owner")
    stranger = add_user("sam", "viewer")
    doc_id = add_doc(owner)
    sam = logged_in(make_client, "sam")

    assert sam.get(f"/documents/{doc_id}/download").status_code == 404
    assert sam.get(f"/documents/{doc_id}/edit").status_code == 404
    assert sam.post(f"/documents/{doc_id}/edit", data={"name": "hacked", "category": "x"}).status_code == 404
    assert sam.get(f"/documents/{doc_id}/permissions").status_code == 404
    assert sam.post(f"/documents/{doc_id}/permissions",
                    data={"username": "sam", "permission": "edit"}).status_code == 404
    assert sam.post(f"/documents/{doc_id}/delete").status_code == 404
    assert sam.post(f"/documents/{doc_id}/restore").status_code == 404
    assert sam.post(f"/documents/{doc_id}/permissions/{stranger}/revoke").status_code == 404

    after = get_doc(doc_id)
    assert after["name"] == "Secret plan" and not after["deleted"]
    assert grants_for(doc_id) == {}


def test_not_signed_in_cannot_reach_documents(client):
    owner = add_user("olivia", "owner")
    doc_id = add_doc(owner)
    response = client.get(f"/documents/{doc_id}/download")
    assert response.status_code == 302 and "/login" in response.headers["Location"]
    assert client.post(f"/documents/{doc_id}/delete").status_code == 302
    assert not get_doc(doc_id)["deleted"]


# ----------------------------------------------------------------------------
# Threat 2: telling "exists but forbidden" from "does not exist"
# ----------------------------------------------------------------------------
def test_nonexistent_and_forbidden_look_identical(make_client):
    owner = add_user("olivia", "owner")
    add_user("sam", "viewer")
    doc_id = add_doc(owner)
    sam = logged_in(make_client, "sam")

    real_but_forbidden = sam.get(f"/documents/{doc_id}/download")
    does_not_exist = sam.get("/documents/99999/download")
    assert real_but_forbidden.status_code == does_not_exist.status_code == 404
    for response in (real_but_forbidden, does_not_exist):
        assert b"couldn&#39;t find that page or document" in response.data or b"find that page" in response.data


# ----------------------------------------------------------------------------
# Threat 3: search / dashboard leaking other people's documents
# ----------------------------------------------------------------------------
def test_dashboard_and_search_never_list_unauthorised_documents(make_client):
    owner = add_user("olivia", "owner")
    sam_id = add_user("sam", "owner")
    add_user("admin1", "admin")
    add_doc(owner, name="TopSecretSalaries", category="Payroll")
    add_doc(sam_id, name="Sam holiday list", category="Personal")
    sam = logged_in(make_client, "sam")

    for url in ("/dashboard", "/dashboard?q=TopSecret", "/dashboard?q=olivia",
                "/dashboard?category=Payroll", "/dashboard?date_from=2000-01-01&date_to=2999-01-01"):
        body = sam.get(url).data
        assert b"TopSecretSalaries" not in body, url
        assert b"Payroll" not in body, url
    assert b"Sam holiday list" in sam.get("/dashboard").data

    admin = logged_in(make_client, "admin1")
    assert b"TopSecretSalaries" in admin.get("/dashboard").data


def test_search_by_name_owner_category_and_date_works(make_client):
    owner = add_user("olivia", "owner")
    add_doc(owner, name="Contract Alpha", category="Contracts")
    add_doc(owner, name="Payslip", category="HR")
    me = logged_in(make_client, "olivia")

    assert b"Contract Alpha" in me.get("/dashboard?q=alpha").data
    assert b"Payslip" not in me.get("/dashboard?q=alpha").data
    assert b"Payslip" in me.get("/dashboard?q=olivia").data               # by owner
    assert b"Contract Alpha" not in me.get("/dashboard?category=HR").data  # by category
    assert b"Payslip" not in me.get("/dashboard?date_from=2999-01-01").data  # by date
    assert b"Payslip" in me.get("/dashboard?date_from=2000-01-01").data


# ----------------------------------------------------------------------------
# Threat 4: a small permission being used for a bigger action
# ----------------------------------------------------------------------------
def test_read_grant_allows_download_but_not_edit_share_delete(make_client):
    owner = add_user("olivia", "owner")
    reader = add_user("rita", "viewer")
    doc_id = add_doc(owner, content=b"hello reader\n")
    grant(doc_id, reader, "read")
    rita = logged_in(make_client, "rita")

    download = rita.get(f"/documents/{doc_id}/download")
    assert download.status_code == 200 and download.data == b"hello reader\n"
    assert rita.get(f"/documents/{doc_id}/edit").status_code == 403
    assert rita.post(f"/documents/{doc_id}/edit", data={"name": "mine now", "category": ""}).status_code == 403
    assert rita.get(f"/documents/{doc_id}/permissions").status_code == 403
    assert rita.post(f"/documents/{doc_id}/permissions",
                     data={"username": "rita", "permission": "edit"}).status_code == 403
    assert rita.post(f"/documents/{doc_id}/delete").status_code == 403
    assert get_doc(doc_id)["name"] == "Secret plan" and not get_doc(doc_id)["deleted"]
    assert grants_for(doc_id) == {reader: "read"}


def test_edit_grant_can_edit_but_not_share_or_delete(make_client):
    owner = add_user("olivia", "owner")
    editor = add_user("eddie", "viewer")
    doc_id = add_doc(owner)
    grant(doc_id, editor, "edit")
    eddie = logged_in(make_client, "eddie")

    assert eddie.get(f"/documents/{doc_id}/edit").status_code == 200
    response = eddie.post(f"/documents/{doc_id}/edit", data={"name": "Renamed by Eddie", "category": "HR"})
    assert response.status_code == 302
    assert get_doc(doc_id)["name"] == "Renamed by Eddie"

    assert eddie.get(f"/documents/{doc_id}/permissions").status_code == 403
    assert eddie.post(f"/documents/{doc_id}/delete").status_code == 403
    assert not get_doc(doc_id)["deleted"]


def test_edit_grant_can_replace_file_and_it_is_audited(make_client):
    owner = add_user("olivia", "owner")
    editor = add_user("eddie", "viewer")
    doc_id = add_doc(owner, content=b"version one\n")
    grant(doc_id, editor, "edit")
    eddie = logged_in(make_client, "eddie")

    response = eddie.post(f"/documents/{doc_id}/edit", data={
        "name": "Secret plan", "category": "HR",
        "file": (__import__("io").BytesIO(b"version two\n"), "plan2.txt")},
        content_type="multipart/form-data")
    assert response.status_code == 302
    assert get_doc(doc_id)["version"] == 2
    assert eddie.get(f"/documents/{doc_id}/download").data == b"version two\n"
    edits = events("document_edit")
    assert len(edits) == 1 and edits[0]["actor_id"] == editor and "file_replaced" in edits[0]["details"]


# ----------------------------------------------------------------------------
# Threat 5: taking access away must work immediately
# ----------------------------------------------------------------------------
def test_revoked_user_is_blocked_on_their_very_next_request(make_client):
    owner = add_user("olivia", "owner")
    reader = add_user("rita", "viewer")
    doc_id = add_doc(owner)
    grant(doc_id, reader, "read")
    rita = logged_in(make_client, "rita")
    olivia = logged_in(make_client, "olivia")

    assert rita.get(f"/documents/{doc_id}/download").status_code == 200
    assert olivia.post(f"/documents/{doc_id}/permissions/{reader}/revoke").status_code == 302
    assert rita.get(f"/documents/{doc_id}/download").status_code == 404      # same session, very next request
    assert b"Secret plan" not in rita.get("/dashboard").data


def test_downgrade_from_edit_to_read_takes_effect_immediately(make_client):
    owner = add_user("olivia", "owner")
    editor = add_user("eddie", "viewer")
    doc_id = add_doc(owner)
    grant(doc_id, editor, "edit")
    eddie = logged_in(make_client, "eddie")
    olivia = logged_in(make_client, "olivia")

    assert eddie.get(f"/documents/{doc_id}/edit").status_code == 200
    olivia.post(f"/documents/{doc_id}/permissions", data={"username": "eddie", "permission": "read"})
    assert eddie.get(f"/documents/{doc_id}/edit").status_code == 403
    assert eddie.post(f"/documents/{doc_id}/edit", data={"name": "nope", "category": ""}).status_code == 403
    assert eddie.get(f"/documents/{doc_id}/download").status_code == 200   # still may read


def test_permission_changes_are_audited(make_client):
    owner = add_user("olivia", "owner")
    reader = add_user("rita", "viewer")
    doc_id = add_doc(owner)
    olivia = logged_in(make_client, "olivia")

    olivia.post(f"/documents/{doc_id}/permissions", data={"username": "rita", "permission": "read"})
    olivia.post(f"/documents/{doc_id}/permissions/{reader}/revoke")
    granted, revoked = events("permission_granted"), events("permission_revoked")
    assert len(granted) == 1 and "after=read" in granted[0]["details"] and granted[0]["actor_id"] == owner
    assert len(revoked) == 1 and f"target_user_id={reader}" in revoked[0]["details"]


# ----------------------------------------------------------------------------
# Threat 6: a leaver keeps a working session
# ----------------------------------------------------------------------------
def test_disabled_user_session_dies_immediately(make_client):
    admin = add_user("admin1", "admin")
    reader = add_user("rita", "viewer")
    owner = add_user("olivia", "owner")
    doc_id = add_doc(owner)
    grant(doc_id, reader, "read")
    rita = logged_in(make_client, "rita")
    boss = logged_in(make_client, "admin1")

    assert rita.get(f"/documents/{doc_id}/download").status_code == 200
    assert boss.post(f"/admin/users/{reader}/toggle").status_code == 302

    response = rita.get(f"/documents/{doc_id}/download")           # old cookie, same browser
    assert response.status_code == 302 and "/login" in response.headers["Location"]
    assert login(make_client(), "rita").status_code == 401         # and cannot sign in again


def test_old_session_stays_dead_after_user_is_re_enabled(make_client):
    """Disabling bumps session_version. If the person is switched back on later,
    the cookie they held before must NOT start working again."""
    add_user("admin1", "admin")
    reader = add_user("rita", "viewer")
    rita = logged_in(make_client, "rita")
    boss = logged_in(make_client, "admin1")
    assert rita.get("/dashboard").status_code == 200

    boss.post(f"/admin/users/{reader}/toggle")        # disable
    boss.post(f"/admin/users/{reader}/toggle")        # enable again
    response = rita.get("/dashboard")                  # the OLD cookie
    assert response.status_code == 302 and "/login" in response.headers["Location"]
    assert login(make_client(), "rita").status_code == 302   # a fresh sign-in works


# ----------------------------------------------------------------------------
# Threat 7: deleted documents
# ----------------------------------------------------------------------------
def test_soft_deleted_document_unreachable_even_for_grantees(make_client):
    owner = add_user("olivia", "owner")
    reader = add_user("rita", "viewer")
    doc_id = add_doc(owner)
    grant(doc_id, reader, "read")
    olivia = logged_in(make_client, "olivia")
    rita = logged_in(make_client, "rita")

    olivia.post(f"/documents/{doc_id}/delete")
    assert rita.get(f"/documents/{doc_id}/download").status_code == 404
    assert b"Secret plan" not in rita.get("/dashboard").data
    assert b"Secret plan" in olivia.get("/documents/trash").data

    olivia.post(f"/documents/{doc_id}/restore")
    assert rita.get(f"/documents/{doc_id}/download").status_code == 200   # grant survived the trash


def test_trash_and_restore_are_private_to_the_owner(make_client):
    owner = add_user("olivia", "owner")
    add_user("sam", "owner")
    doc_id = add_doc(owner)
    logged_in(make_client, "olivia").post(f"/documents/{doc_id}/delete")
    sam = logged_in(make_client, "sam")

    assert b"Secret plan" not in sam.get("/documents/trash").data
    assert sam.post(f"/documents/{doc_id}/restore").status_code == 404
    assert get_doc(doc_id)["deleted"]


# ----------------------------------------------------------------------------
# Threat 8 / 9: roles
# ----------------------------------------------------------------------------
def test_registration_cannot_create_owner_or_admin(client):
    for wanted in ("admin", "owner"):
        response = client.post("/register", data={
            "username": f"sneaky_{wanted}", "password": "LongEnough#1", "role": wanted})
        assert response.status_code == 302
        with app_module.app.app_context():
            assert User.query.filter_by(username=f"sneaky_{wanted}").one().role == "viewer"


def test_viewer_cannot_upload_or_open_admin_pages(make_client):
    add_user("rita", "viewer")
    add_user("olivia", "owner")
    for who in ("rita", "olivia"):
        person = logged_in(make_client, who)
        assert person.get("/admin/audit").status_code == 403
        assert person.get("/admin/users").status_code == 403
        assert person.post("/admin/users", data={"username": "x", "password": "a" * 12, "role": "admin"}).status_code == 403
    rita = logged_in(make_client, "rita")
    assert rita.get("/documents/upload").status_code == 403
    assert upload(rita, "a.txt", b"hello").status_code == 403
    with app_module.app.app_context():
        assert Document.query.count() == 0
        assert User.query.filter_by(username="x").count() == 0


def test_admin_can_create_accounts_and_cannot_disable_self(make_client):
    admin = add_user("admin1", "admin")
    boss = logged_in(make_client, "admin1")
    boss.post("/admin/users", data={"username": "newowner", "password": "LongPassword#1", "role": "owner"})
    with app_module.app.app_context():
        assert User.query.filter_by(username="newowner").one().role == "owner"
    boss.post(f"/admin/users/{admin}/toggle")
    with app_module.app.app_context():
        assert db.session.get(User, admin).active is True


# ----------------------------------------------------------------------------
# Threat 10: the audit trail cannot be quietly changed
# ----------------------------------------------------------------------------
def test_audit_rows_cannot_be_updated_or_deleted(make_client):
    owner = add_user("olivia", "owner")
    add_doc(owner)
    with app_module.app.app_context():
        assert AuditEvent.query.count() >= 1
        with pytest.raises(DBAPIError):
            db.session.execute(text("UPDATE audit_events SET details = 'edited'"))
        db.session.rollback()
        with pytest.raises(DBAPIError):
            db.session.execute(text("DELETE FROM audit_events"))
        db.session.rollback()
        assert AuditEvent.query.filter_by(details="edited").count() == 0


def test_hash_chain_detects_tampering(make_client):
    owner = add_user("olivia", "owner")
    add_doc(owner)
    add_doc(owner, name="Second")
    with app_module.app.app_context():
        ok, bad_id, count = app_module.verify_audit_chain()
        assert ok and bad_id is None and count >= 2

        # Someone with full database access removes the safety rule and edits an old entry...
        db.session.execute(text("DROP TRIGGER audit_no_update"))
        first_id = AuditEvent.query.order_by(AuditEvent.id).first().id
        db.session.execute(text("UPDATE audit_events SET details = 'nothing to see' WHERE id = :i"), {"i": first_id})
        db.session.commit()

        # ...and the chain check shows exactly where.
        ok, bad_id, _ = app_module.verify_audit_chain()
        assert not ok and bad_id == first_id


def test_admin_page_shows_broken_chain(make_client):
    owner = add_user("olivia", "owner")
    add_user("admin1", "admin")
    add_doc(owner)
    boss = logged_in(make_client, "admin1")
    assert b"check out" in boss.get("/admin/audit").data
    with app_module.app.app_context():
        db.session.execute(text("DROP TRIGGER audit_no_update"))
        db.session.execute(text("UPDATE audit_events SET details = 'x' WHERE id = 1"))
        db.session.commit()
    assert b"chain is broken" in boss.get("/admin/audit").data


# ----------------------------------------------------------------------------
# Threat 11 / 12: refusals are recorded, admin reads are flagged
# ----------------------------------------------------------------------------
def test_refused_attempts_are_in_the_audit_trail(make_client):
    owner = add_user("olivia", "owner")
    sam = add_user("sam", "viewer")
    reader = add_user("rita", "viewer")
    doc_id = add_doc(owner)
    grant(doc_id, reader, "read")

    logged_in(make_client, "sam").get(f"/documents/{doc_id}/download")
    logged_in(make_client, "rita").post(f"/documents/{doc_id}/delete")
    logged_in(make_client, "sam").get("/documents/424242/download")
    login(make_client(), "sam", "wrong-password")

    denied_downloads = events("download_denied")
    assert any(e["actor_id"] == sam and e["document_id"] == doc_id and "no_access" in e["details"]
               for e in denied_downloads)
    assert any("not_found" in e["details"] for e in denied_downloads)
    delete_denied = events("delete_denied")
    assert len(delete_denied) == 1 and delete_denied[0]["actor_id"] == reader
    assert "insufficient_access" in delete_denied[0]["details"]
    assert any(e["actor_id"] == sam for e in events("login_denied"))


def test_successful_actions_are_audited(make_client):
    owner = add_user("olivia", "owner")
    olivia = logged_in(make_client, "olivia")
    upload(olivia, "a.txt", b"hello", name="Hello doc")
    doc_id = 1
    olivia.get(f"/documents/{doc_id}/download")
    olivia.post(f"/documents/{doc_id}/delete")
    seen = {e["action"] for e in events()}
    assert {"login_success", "upload", "download", "delete"} <= seen


def test_admin_downloading_unshared_document_is_flagged(make_client):
    owner = add_user("olivia", "owner")
    add_user("admin1", "admin")
    doc_id = add_doc(owner)

    logged_in(make_client, "olivia").get(f"/documents/{doc_id}/download")
    boss = logged_in(make_client, "admin1")
    assert boss.get(f"/documents/{doc_id}/download").status_code == 200

    downloads = events("download")
    assert "admin_override" not in downloads[0]["details"]      # the owner's own download
    assert "admin_override=1" in downloads[1]["details"]        # the admin's
    assert b"opened document" in boss.get("/admin/audit").data


# ----------------------------------------------------------------------------
# Threat 13 / 14: uploads
# ----------------------------------------------------------------------------
@pytest.mark.parametrize("filename,content", [
    ("virus.exe", b"MZ\x90\x00 pretend program"),                    # wrong extension
    ("report.pdf", b"MZ\x90\x00 this is not a pdf"),                  # right name, wrong bytes
    ("page.html", b"<script>alert(1)</script>"),                      # active content
    ("photo.png", b"GIF89a not a png"),
    ("letter.docx", b"just some text, not a zip"),                    # fake docx
    ("notes.txt", b"binary\x00inside"),                               # NUL bytes in "text"
    ("empty.txt", b""),
    ("noextension", b"hello"),
])
def test_upload_rejects_wrong_extension_and_spoofed_content(make_client, filename, content):
    add_user("olivia", "owner")
    olivia = logged_in(make_client, "olivia")
    response = upload(olivia, filename, content)
    assert response.status_code == 400
    with app_module.app.app_context():
        assert Document.query.count() == 0
    assert os.listdir(app_module.app.config["UPLOAD_FOLDER"]) == []
    assert any(e["action"] == "upload_rejected" for e in events())


def test_upload_rejects_files_over_the_size_limit(make_client):
    add_user("olivia", "owner")
    olivia = logged_in(make_client, "olivia")
    response = upload(olivia, "big.txt", b"a" * (app_module.MAX_FILE_SIZE + 10))
    assert response.status_code in (400, 413)
    with app_module.app.app_context():
        assert Document.query.count() == 0


def test_upload_accepts_real_files_and_keeps_original_filename(make_client):
    add_user("olivia", "owner")
    olivia = logged_in(make_client, "olivia")
    pdf = b"%PDF-1.4\n%fake but valid header\n"

    assert upload(olivia, "../../etc/evil name.pdf", pdf, name="Agreement", category="Legal").status_code == 302
    assert upload(olivia, "letter.docx", fake_docx()).status_code == 302

    first = get_doc(1)
    assert first["original_filename"] == "etc_evil_name.pdf"                 # path parts stripped
    assert re.fullmatch(r"[0-9a-f]{48}", first["storage_name"])             # random name on disk
    assert os.path.isfile(os.path.join(app_module.app.config["UPLOAD_FOLDER"], first["storage_name"]))

    response = olivia.get("/documents/1/download")
    assert response.status_code == 200 and response.data == pdf
    assert "attachment" in response.headers["Content-Disposition"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_files_are_not_served_from_static(client, make_client):
    add_user("olivia", "owner")
    doc_id = add_doc(1)
    storage = get_doc(doc_id)["storage_name"]
    assert client.get(f"/static/{storage}").status_code == 404
    assert client.get(f"/static/../instance/private_uploads/{storage}").status_code == 404


# ----------------------------------------------------------------------------
# Threat 15: CSRF
# ----------------------------------------------------------------------------
def test_state_changing_posts_require_csrf_token(app, make_client):
    owner = add_user("olivia", "owner")
    doc_id = add_doc(owner)
    olivia = logged_in(make_client, "olivia")         # logged in while CSRF is off

    app.config["WTF_CSRF_ENABLED"] = True              # now behave like the real site
    assert olivia.post(f"/documents/{doc_id}/delete").status_code == 400
    assert olivia.post(f"/documents/{doc_id}/permissions",
                       data={"username": "x", "permission": "read"}).status_code == 400
    assert make_client().post("/login", data={"username": "olivia", "password": PASSWORD}).status_code == 400
    assert olivia.post("/logout").status_code == 400
    assert not get_doc(doc_id)["deleted"]


# ----------------------------------------------------------------------------
# Threat 16: password guessing
# ----------------------------------------------------------------------------
def test_login_brute_force_is_rate_limited(make_client):
    add_user("olivia", "owner")
    add_user("sam", "viewer")
    attacker = make_client()
    for _ in range(app_module.LOGIN_MAX_FAILURES):
        assert login(attacker, "olivia", "wrong").status_code == 401
    assert login(attacker, "olivia", PASSWORD).status_code == 429       # even the right password is paused
    assert any(e["action"] == "login_rate_limited" for e in events())
    assert login(make_client(), "sam").status_code == 302               # other accounts are unaffected


def test_unknown_user_and_wrong_password_look_the_same(client):
    add_user("olivia", "owner")
    unknown = login(client, "nobody", "whatever")
    wrong = login(client, "olivia", "whatever")
    assert unknown.status_code == wrong.status_code == 401
    assert b"Username or password" in unknown.data and b"Username or password" in wrong.data


# ----------------------------------------------------------------------------
# Threat 18: stored XSS, plus security headers
# ----------------------------------------------------------------------------
def test_document_names_are_escaped_on_every_page(make_client):
    owner = add_user("olivia", "owner")
    add_user("admin1", "admin")
    payload = "<script>alert(1)</script>"
    doc_id = add_doc(owner, name=payload, category="<img src=x onerror=alert(1)>")
    olivia = logged_in(make_client, "olivia")
    boss = logged_in(make_client, "admin1")

    pages = [olivia.get("/dashboard"), olivia.get(f"/documents/{doc_id}/edit"),
             olivia.get(f"/documents/{doc_id}/permissions"), boss.get("/admin/audit"), boss.get("/dashboard")]
    for response in pages:
        assert response.status_code == 200
        assert payload.encode() not in response.data
        assert b"<img src=x" not in response.data
    assert b"&lt;script&gt;" in pages[0].data


def test_security_headers_are_set(make_client):
    add_user("olivia", "owner")
    olivia = logged_in(make_client, "olivia")
    response = olivia.get("/dashboard")
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
