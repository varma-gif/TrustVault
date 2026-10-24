# AI prompt log

TODO BEFORE SUBMITTING: every entry below must be a REAL event. Delete any you cannot truthfully
fill in. Need at least 5 dated entries, at least 2 about authorisation / access control / audit,
each with a commit link. Replace this notice.

Commits that exist in this project (link as https://github.com/<you>/<repo>/commit/<hash>):
- e7b6615  Final Flask version (main build, includes tests)
- 85acc97  Read demo passwords from DEMO_PASSWORD env var
- b2228f6  README: live demo section, deploy steps, known limits
(After you push to your new repo, check these hashes still match.)

## Entry 1 - YYYY-MM-DD - <topic: authorisation>
- Prompt / summary:
- Produced:
- What was wrong (specific):
- What I did instead (commit link):

## Entry 2 - YYYY-MM-DD - <topic: audit trail>
- Prompt / summary:
- Produced:
- What was wrong (specific):
- What I did instead (commit link):

## Entry 3 - YYYY-MM-DD - <topic: tests / upload checks / demo passwords>
- Prompt / summary:
- Produced:
- What was wrong (specific):
- What I did instead (commit link):

## Entry 4 - YYYY-MM-DD -
## Entry 5 - YYYY-MM-DD -

## Reusable project context (reused across the week)
- Stack: Python, Flask, Flask-Login, Flask-SQLAlchemy, SQLite, Jinja templates.
- Rule: authorization must be checked server-side on every document route.
- Rule: private files must not be served from `static/`.
- Rule: never claim a security test passes until it has been run.
- Rule: record known limitations honestly.
