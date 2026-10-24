# AI prompt log

I used Claude (claude.ai chat) to review, document and deploy this project, and earlier I used AI assistants
while building it. This log has the sessions I can describe in detail. Each entry says what I asked, what
the AI did, what was wrong or missing, and what I did about it.

The GitHub repo was re-created before submission, so the history is short. Commit links point at the
commits that exist now.

## Entry 1 - 2026-10-24 - Authorization review (access control)
- **What I asked:** I uploaded the whole project and asked Claude to check it against the task requirements
  and tell me what to change.
- **What it did:** It unzipped the project, ran my 40 tests (all passed), read `authorize()` and every
  document route, then cloned the repo fresh, started it and tried the protected pages while logged out.
  `/dashboard`, `/documents/1/download`, `/documents/trash`, `/admin/audit` and `/admin/users` all redirected
  to login, and a path trick to reach the database file under `/static` gave 404.
- **What was wrong or missing:** It found no hole in the authorization code. But it only checked what could
  be tested from outside and with the test suite. It did not re-run the "remove the check and see the tests
  fail" experiments that my THREATS.md describes, and it could not log in as the different roles.
- **What I did:** No code change was needed. The evidence is `tests/test_security.py` in commit
  [6c3a874](https://github.com/varma-gif/TrustVault/commit/6c3a874). I still need to do the
  removal check myself before the interview: comment out the `authorize()` call in the download route, run
  `pytest`, and confirm tests fail.

## Entry 2 - 2026-10-24 - Audit trail in the database schema file
- **What I asked:** The task needs database schema and setup scripts, so I asked Claude to produce a
  `schema.sql`.
- **What it did:** It generated the table definitions from `models.py`.
- **What was wrong:** The first version had only the tables. The triggers that stop anyone from editing or
  deleting audit rows are created separately, so a person using only that schema file would get an
  unprotected audit log. Claude noticed this and added the two triggers (`audit_no_update`, `audit_no_delete`)
  from `models.py` before giving me the file.
- **What I did:** I used the corrected `schema.sql`, which includes the triggers. It is in commit
  [6c3a874](https://github.com/varma-gif/TrustVault/commit/6c3a874). Honest note: Claude caught this
  mistake itself, not me. I still need to confirm with a test that the triggers refuse UPDATE and DELETE.

## Entry 3 - 2026-10-25 - Demo accounts on the public site
- **What I asked:** How to deploy on Render and keep the live demo accounts safe.
- **What it did:** It told me to set `DEMO_PASSWORD`, so that the public local passwords in my README
  (like `AdminDemo#2026!`) would not work on the live admin account.
- **What was wrong:** In the first Render instructions Claude said the password needed at least 12 characters
  with upper case, lower case, a number and a symbol. It had not read the code. When I checked, `seed-demo`
  accepts any value for `DEMO_PASSWORD`, with no strength check. Claude then corrected itself.
- **What I did:** I set `DEMO_PASSWORD` in Render so the live site does not use the README's local passwords,
  and I put the live login table in the README, because the task asks for credentials there. Claude
  recommended a random password. I chose my own, which is weaker, and accepted that because the live accounts
  only hold fake data. README commit: [06dea14](https://github.com/varma-gif/TrustVault/commit/06dea14).

## Reusable project context
- Stack: Python, Flask, Flask-Login, Flask-SQLAlchemy, SQLite, Jinja templates.
- Rule: authorization must be checked server-side on every document route.
- Rule: private files must not be served from `static/`.
- Rule: never claim a security test passes until it has been run.
- Rule: record known limitations honestly.