# THREATS

Format: threat → what I did → test → status. "Accepted" entries are known gaps.

| # | Threat | Mitigation | Test | Status |
|---|---|---|---|---|
| 1 | IDOR: guess `/documents/<id>/...` for any route (download, edit, share, delete, restore, revoke) | `authorize()` is called first in every document route and decides from the DB | `test_stranger_cannot_download_edit_share_delete` | Closed |
| 2 | ID enumeration via 403-vs-404 | No-access and missing both return 404; both audited | `test_nonexistent_and_forbidden_look_identical` | Closed (IDs still sequential; accepted) |
| 3 | Search/dashboard leaks titles or owners of other people's documents | Search is a SQL query restricted to owner/granted/admin before any filter is applied | `test_dashboard_and_search_never_list_unauthorised_documents` | Closed |
| 4 | Read grant used to edit/share/delete | Levels ranked read < edit < manage | `test_read_grant_allows_download_but_not_edit_share_delete`, `test_edit_grant_can_edit_but_not_share_or_delete` | Closed |
| 5 | Revoked user keeps access via open session or saved URL | No signed URLs/tokens; grant re-read from DB on every request | `test_revoked_user_is_blocked_on_their_very_next_request`, `test_downgrade_...` | Closed |
| 6 | Leaver keeps working session | `active` flag + `session_version` checked in `load_user` on every request | `test_disabled_user_session_dies_immediately` | Closed |
| 7 | Deleted document still reachable by grantees | Soft delete; every query excludes `deleted_at` | `test_soft_deleted_document_unreachable_even_for_grantees` | Closed |
| 8 | Self-register as admin/owner (mass assignment) | Role is never read from the form | `test_registration_cannot_create_owner_or_admin` | Closed |
| 9 | Viewer calls owner/admin endpoints directly | `role_required` on the server | `test_viewer_cannot_upload_...` | Closed |
| 10 | Audit rows edited/deleted | SQLite triggers abort UPDATE/DELETE; hash chain detects edits; admin page verifies | `test_audit_rows_cannot_be_updated_or_deleted`, `test_hash_chain_detects_tampering` | Partly closed: someone with full server/file access can drop the triggers AND recompute the whole chain. **Accepted.** Mitigation I would add: periodically publish the latest hash somewhere outside the server. |
| 11 | Refused attempts not recorded | Every refusal writes `*_denied` before aborting | `test_refused_attempts_are_in_the_audit_trail` | Closed |
| 12 | Admin quietly reads everything | Admin reads are audited and listed under `admin_override` | `test_admin_downloading_unshared_document_is_flagged` | Detected, not prevented. Admin is trusted by design. |
| 13 | Spoofed/malicious upload (renamed exe, HTML as .pdf, fake docx, zip bomb) | Extension allow-list + magic-byte check + zip entry/size limits; random storage name; `nosniff`; always `attachment` | `test_upload_rejects_wrong_extension_and_spoofed_content` (8 cases), `test_upload_rejects_files_over_the_size_limit` | Closed for types listed. Rejected uploads are written to the audit trail as `upload_rejected`. **No antivirus scan**: accepted. |
| 14 | Path traversal via filename | Storage name is random hex; user filename only used as download name after `secure_filename` | `test_upload_accepts_real_files_and_keeps_original_filename` | Closed |
| 15 | CSRF | Flask-WTF on all POSTs; SameSite=Lax | `test_state_changing_posts_require_csrf_token` | Closed |
| 16 | Password guessing | 5 failures / 15 min per IP+username; same message and timing for unknown user | `test_login_brute_force_is_rate_limited` | Limiter is in-process memory (resets on restart, not shared across workers). Accepted. On Render/Railway set `TRUSTVAULT_PROXY_HOPS=1`, otherwise every visitor looks like the same address. |
| 17 | Files readable straight from disk / DB | Stored outside `static/`; random names; not encrypted at rest | `test_files_are_not_served_from_static` (web route only) | **Accepted**: server compromise = file compromise. |
| 18 | Stored XSS via document/category names | Jinja autoescape; strict CSP (no inline script; the delete pop-up lives in `static/js/app.js`) | `test_document_names_are_escaped_on_every_page`, `test_security_headers_are_set` | Closed |
| 19 | Concurrent audit writes fork the chain | In-process lock, unique `prev_hash`, single gunicorn worker | none | Works only with 1 worker. Accepted. |
| 20 | Username enumeration at registration | Returns "taken" | none | **Accepted** (open registration is the cause). |
| 21 | Hard-coded demo passwords | Only created by `seed-demo`; never run in production | none | Accepted for the demo deployment. |
| 22 | Someone locks a victim out by typing 5 wrong passwords for their username | Limiter counts per (address, username), so it only pauses that one pairing for 15 minutes | `test_login_brute_force_is_rate_limited` (other accounts unaffected) | **Accepted**: a nuisance, not a leak. Needs the real visitor address (see 16). |
| 23 | Newest audit entries deleted/replaced along with the whole chain, or database without triggers (Postgres etc.) | Triggers exist for SQLite only. Admin page shows the newest fingerprint so it can be written down elsewhere | `test_hash_chain_detects_tampering`, `test_admin_page_shows_broken_chain` | **Accepted.** Cutting off the tail is only detectable if someone noted an earlier fingerprint. |
| 24 | Replacing a file destroys the old version (no history) | The audit trail keeps the hash of every version, but not the content | `test_edit_grant_can_replace_file_and_it_is_audited` | **Accepted**: no version history was built. |
| 25 | Re-enabled leaver's old cookie works again | `session_version` is bumped on disable, so cookies from before are dead for good | `test_old_session_stays_dead_after_user_is_re_enabled` | Closed |
| 26 | Unlimited self-registration (spam accounts) | Accounts are viewers only and see nothing until shared with | `test_registration_cannot_create_owner_or_admin` | **Accepted**: no CAPTCHA or email check. |
| 27 | No password change / reset, no way to change a role | Admin can create accounts and disable people | none | **Accepted**: not built. Re-create the account with the right role. |

## Mutation check (do this before submitting)
Remove one check and confirm a test fails. Done on 40 tests, one at a time (each time the original was restored):

| Check removed | Tests that failed |
|---|---|
| `if level is None: ... abort(404)` in `authorize()` | 5 |
| the `LEVEL_RANK < NEEDED_RANK` check (read could do anything) | 4 |
| `if session.get("sv") != user.session_version` in `load_user` | 1 (`test_old_session_stays_dead_after_user_is_re_enabled`) |
| `deleted_at` check in `authorize()` | 1 |
| search restricted to visible documents | 2 |
| audit write for `no_access` refusals | 1 |
| revoke actually deleting the grant | 1 |

Lesson: the first version of the suite did NOT catch the `session_version` mutation, because the `active` flag hides it. The re-enable test was added for that reason.
