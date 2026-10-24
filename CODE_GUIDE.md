# TrustVault - Code Guide (plain English, for explaining to HR)

## 1. The 30-second story
TrustVault lets a company share confidential documents. Two promises:
1. **Only people who were given access can open a document**, and the server checks this every single time, not just the button on the page.
2. **Everything is written in a diary (audit log)**, including refused attempts, and the diary can't be quietly edited.

## 2. What each file does
| File | What it is | In one line |
|---|---|---|
| `app.py` | The brain | All pages, the permission check, upload checks, audit log |
| `models.py` | The database tables | Users, Documents, Permissions, Audit diary |
| `templates/*.html` | What the user sees | Login page, dashboard, edit page, admin pages... |
| `static/css/style.css` | Colours and layout | Only looks, no logic |
| `static/js/app.js` | Tiny script | The "Are you sure?" pop-up on delete |
| `tests/test_security.py` | Automatic checks | Proves a stranger cannot reach someone else's file (40 tests) |
| `tests/helpers.py` | Test helpers | Small functions like `add_user`, `add_doc`, `login` so tests read like sentences |
| `tests/conftest.py` | Test setup | Builds a fresh fake database before each test |
| `README.md` | How to run it | Install, run, deploy, demo logins |
| `THREATS.md` | Known attacks | What could go wrong, what I did, what I accepted |
| `PROMPTS.md` | AI log | Where AI helped and where it was wrong |

## 3. The three roles
- **Viewer**: sees only documents shared with them.
- **Owner**: uploads documents, shares them (read / edit), takes access back, deletes and restores their own.
- **Admin**: sees everything, manages users, reads the audit diary. When an admin opens a document nobody shared with them, it is flagged.

Per-document permissions: **read** = download. **edit** = download + rename / change category / replace file. Neither can share or delete.

## 4. How a download works (the interview question)
1. Browser asks for `/documents/5/download`.
2. `load_user()` confirms the person is logged in and not disabled.
3. `download_document()` calls **`authorize(5, "read", "download")`**.
4. `authorize()` looks in the database: is this the owner? an admin? is there a permission row?
5. If NO -> the refusal is written to the audit log and the user gets "not found" (404).
6. If YES -> the download is written to the audit log, then the file is sent.

**If the `authorize()` line were removed:** any logged-in person could download any document by guessing the number. The tests would fail, which is why they exist.

## 5. Why revoking works immediately
We never hand out special links or long-lived tickets. Every request re-reads the permission table. Delete the row -> the very next request is refused.
Disabling a user also changes their `session_version`, so every login cookie they hold stops working.

## 6. Why the audit diary is hard to tamper with
- The database has rules that **refuse any edit or delete** on the diary table.
- Each entry stores a fingerprint (hash) of itself + the previous entry. Change one old entry and every fingerprint after it no longer matches. The admin page re-checks this and shows a tick or a warning.
- **Honest limit:** someone with full control of the server could remove the rules and rewrite the whole chain. A real company would also copy the latest fingerprint to another system. (Listed in THREATS.md.)

## 6b. "I want to change X - where do I go?"
| I want to... | Go to | Look for |
|---|---|---|
| Change who may do what to a document | `app.py` | `authorize()`, `access_level()`, `NEEDED_RANK` |
| Add an allowed file type | `app.py` | `ALLOWED_EXTENSIONS`, `MIME_BY_EXT`, `validate_content()` |
| Change max file size | `app.py` | `MAX_FILE_SIZE` |
| Change login attempt limit | `app.py` | `LOGIN_MAX_FAILURES`, `LOGIN_WINDOW_SECONDS` |
| Change what gets logged | `app.py` | `audit(` calls inside each page function |
| Change what admin flags as suspicious | `app.py` | `admin_audit()` ("Worth noticing") |
| Add a column to a table | `models.py` | the matching class (then delete `instance/trustvault.db` while developing) |
| Change page text or layout | `templates/` | the matching `.html` file |
| Change colours | `static/css/style.css` | the `:root` block at the very top (`--accent`, `--paper`, ...) |
| Change fonts | `templates/base.html` + `static/css/style.css` | the Google Fonts `<link>`, and `--font-heading` / `--font-body` |
| Change the "Are you sure?" message | the form in `templates/` | the `data-confirm="..."` attribute (script is `static/js/app.js`) |

## 7. Things I deliberately did NOT build (say this proudly)
Folders and groups, sharing with people outside the company, encryption of files on disk, virus scanning, two-factor login, permanent purge / retention rules, AI sharing suggestions. A smaller system that holds is better than a bigger one with a hole.

## 8. Honest known limits
- Behind Render/Railway set `TRUSTVAULT_PROXY_HOPS=1`, or the login limiter treats every visitor as one address.
- Replacing a file deletes the old version (only its hash stays in the diary).
- Login-attempt limiter and audit lock work for one server process (so run one gunicorn worker).
- Document numbers are sequential (but guessing them gets you nothing: strangers just see "not found").
- Files are stored unencrypted on the server's disk.
