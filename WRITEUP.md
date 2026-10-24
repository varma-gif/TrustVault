# TrustVault - write-up

## What I built
A Flask + SQLite document-sharing app. Owners upload documents and share them with named users as
`read` or `edit`, and can revoke at any time. Admins see everything and manage users. Every action,
including refused attempts, goes into a hash-chained audit log that SQLite triggers protect from
UPDATE/DELETE. 40 automated tests cover access control, revocation, audit and uploads.

## What I deliberately did not build
Folders/groups, external sharing links, encryption at rest, antivirus, 2FA, password reset,
file version history, multi-tenancy (see README "Not built" and THREATS.md "Accepted").

## Permission model (my words)
Access to a document = I own it, or I am an admin, or a row exists in `document_permissions`.
`authorize()` in `app.py` decides this from the database on every document request. No document
route runs without it. No grant means 404 (so IDs cannot be probed); too little access means 403.
Both are audited. Nothing about permissions is cached or put in a URL, so revoking works on the
very next request.

## How I used AI and where it was wrong
I used Claude (claude.ai chat) to review the project, write the schema file and help with deployment.
Earlier, while building, I also used AI assistants (see README). The detailed log is in `PROMPTS.md`.

Where it was wrong or incomplete:
- The first `schema.sql` had no audit-log triggers, so it would have left the audit table editable.
  Claude fixed that before I used the file.
- Claude told me the demo password had to meet a strength rule it had not checked. The code accepts any value.
- Its authorization review found no problem, but it could only test from outside and with my test
  suite, so I still verify the checks myself.

I have not yet written up my earlier build sessions in detail.

## What is unfinished
- Single gunicorn worker only (login limiter and audit lock are per-process).
- On free hosting the database and uploads are lost on restart; demo accounts are re-seeded on start.
- No password change/reset; replacing a file deletes the old version (hash stays in the audit log).