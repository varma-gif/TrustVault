# TrustVault

Secure document sharing with per-document permissions and a tamper-evident audit trail. Built with Flask and SQLite.

**What it does:** users upload documents, share them with specific registered users (read or edit), and take access back at any time. The server checks permission on every request and writes every action, including refused attempts, to an audit log.

## Live demo

- **Live site:** https://trustvault-qboj.onrender.com
- **Demo video (5 min):** https://drive.google.com/file/d/1J351y2TvY2-mOxEX6PZaMbCaXTOPmFob/view?usp=sharing
- **Demo logins for the live site** (fake data only; all four accounts use the same password):

| Role | Username | Password |
|---|---|---|
| Administrator | admin_demo | 23JR1A44B0genai@45 |
| Document owner | owner_demo | 23JR1A44B0genai@45 |
| Viewer (has read access to "Shared salary letter") | viewer_demo | 23JR1A44B0genai@45 |
| Viewer (no access to anything) | viewer_two | 23JR1A44B0genai@45 |

- **Heads up:** on the free hosting tier the database and uploaded files are wiped whenever the service restarts or redeploys, and the first page load after a sleep can take about a minute.

## Run locally (VS Code terminal)

Windows PowerShell:
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SECRET_KEY="change-me-to-a-long-random-value"
$env:FLASK_DEBUG="1"             # local only
flask --app app seed-demo        # creates demo accounts + 2 sample documents
flask --app app run
```
Then open http://127.0.0.1:5000

macOS / Linux:
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="change-me-to-a-long-random-value"
export FLASK_DEBUG=1
flask --app app seed-demo
flask --app app run
```

Generate a real key with `python -c "import secrets; print(secrets.token_hex(32))"`. The app refuses to start without `SECRET_KEY` unless `FLASK_DEBUG=1`.

If PowerShell blocks the activate script, run `Set-ExecutionPolicy -Scope Process Bypass` first.

## Tests
```bash
pytest -v        # 40 tests, about 20 seconds
```
The tests build a fresh temporary database each time and never touch real data. They cover one person reaching another's documents, revoking, disabling people, the audit trail, uploads, CSRF, login limits and XSS (the matching test name is next to each row in `THREATS.md`).

## Demo accounts (local demo data only)

Created by `flask --app app seed-demo`. These passwords are public, so use them **only on your own computer** with fake data.

| Role | Username | Password |
|---|---|---|
| Administrator | admin_demo | AdminDemo#2026! |
| Document owner | owner_demo | OwnerDemo#2026! |
| Viewer (has read access to "Shared salary letter") | viewer_demo | ViewerDemo#2026! |
| Viewer (no access to anything) | viewer_two | ViewerTwo#2026! |

**On the live site the demo passwords are different.** If the environment variable `DEMO_PASSWORD` is set, `seed-demo` gives all four accounts that password instead of the ones above. The live password is listed in the "Live demo" section at the top.

For anything real, do not use `seed-demo`. Run `flask --app app create-admin` and then create owners from the admin Users page.

## Deploy (Render / Railway)

- **Build command:** `pip install -r requirements.txt`
- **Start command:** `gunicorn app:app --workers 1 --threads 4`
  (**1 worker**: the audit hash chain is serialised with an in-process lock.)
- **Demo deployment start command** (creates the demo accounts on every start, useful because free tiers have no shell and lose data on restart):
  `flask --app app seed-demo; gunicorn app:app --workers 1 --threads 4`
- **Environment variables:**

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Required. Signs login cookies. Use a long random value. |
| `COOKIE_SECURE=1` | Send cookies only over HTTPS. |
| `TRUSTVAULT_PROXY_HOPS=1` | So the login limiter sees real visitor addresses behind the host's proxy (leave unset locally). |
| `DEMO_PASSWORD` | Demo deployment only. Password for the seeded demo accounts. Never commit it. |
| `TRUSTVAULT_DB_URI`, `TRUSTVAULT_UPLOAD_FOLDER` | Optional. Point at a persistent disk, e.g. `sqlite:////data/trustvault.db` and `/data/uploads`. |

Without a persistent disk, accounts, documents and the audit trail are lost on redeploy.

## Roles

- **Viewer**: sees only documents shared with them. Self-registration creates viewers only, so a newly registered user cannot upload until an admin creates an owner account for them.
- **Owner**: uploads; full control of their own documents; can share (read/edit) and revoke; can edit/delete; can restore from trash.
- **Admin**: sees all documents and the audit trail, and manages users (create / disable). Any admin download of a document they were not granted is flagged `admin_override`.
- **Per-document grants**: `read` = download. `edit` = download + rename/re-categorise/replace file. Neither can share or delete.

## Endpoints and who may call them

All routes except `/`, `/login`, `/register` need a session. Document routes return **404** if you have no access at all (hides existence) and **403** if you have some access but not enough. Every refusal is audited.

| Endpoint | Method | Allowed |
|---|---|---|
| `/register`, `/login` | GET/POST | anyone (login rate-limited) |
| `/logout` | POST | signed-in |
| `/dashboard` | GET | signed-in; lists only documents you can read |
| `/documents/upload` | GET/POST | owner, admin |
| `/documents/<id>/download` | GET | read grant, owner, admin |
| `/documents/<id>/edit` | GET/POST | edit grant, owner, admin |
| `/documents/<id>/permissions` (+ `/<uid>/revoke`) | GET/POST | owner, admin |
| `/documents/<id>/delete`, `/restore` | POST | owner, admin |
| `/documents/trash` | GET | owner (own), admin (all) |
| `/admin/audit` | GET | admin |
| `/admin/users`, `/admin/users/<id>/toggle` | GET/POST | admin |

## Permission model (in my words)

Per-document grants. Access = owner, or admin, or a row in `document_permissions`. One function, `authorize()` in `app.py`, makes the decision for every document route, on every request, from the database. Nothing is cached in the session except an `sv` counter that lets an admin end a user's sessions.

Revocation cost: one extra database lookup per request. No long-lived tokens or signed URLs exist, so there is nothing to invalidate.

## Audit trail

Every upload, download, share, revoke, edit, delete, login and refused attempt is recorded. Each entry stores a hash that also covers the previous entry, and SQLite triggers refuse edits or deletes on the table. The admin audit page re-checks the chain and shows whether it is intact. Limit: someone with full control of the server could remove the triggers and rewrite the whole chain (see `THREATS.md`).

## Known limits and what is unfinished

- **Storage is local.** SQLite and uploaded files live on the server's disk. On a host without a persistent disk they do not survive a restart or redeploy.
- **Not multi-tenant.** There are no companies or organisations. All users share one workspace, separated by roles and per-document grants.
- **Single worker only.** The login limiter and audit lock work per process, so run one gunicorn worker.
- **No password change or reset.** An admin can create and disable accounts.
- **Files are not encrypted on disk** and there is no antivirus scanning.
- **Replacing a file deletes the old version.** Only its hash stays in the audit log.
- More security edge cases still need testing. The full list of known gaps and accepted risks is in `THREATS.md`.

## Not built (deliberately)

Folders/groups/inheritance, external-user sharing links, file encryption at rest, antivirus scanning, 2FA, permanent purge / retention policy, AI sharing suggestions.

## How AI was used

I used AI assistants (ChatGPT and Claude) while building and reviewing this project. What I asked, what they got wrong, and what I did about it are recorded in `PROMPTS.md`.

## Look and feel

Warm cream and terracotta colours with Fraunces (headings) and Nunito Sans (text). Colours and fonts are listed at the top of `static/css/style.css`; the font link is in `templates/base.html`.