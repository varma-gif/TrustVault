"""
conftest.py - shared setup for all tests.

Before every test we build a brand-new empty database and an empty upload folder,
so tests can never affect each other.
"""
import os
import shutil
import sys
import tempfile

# ---- These must be set BEFORE app.py is imported (app.py reads them at start-up) ----
_TMP = tempfile.mkdtemp(prefix="trustvault_test_")
os.environ["TRUSTVAULT_TESTING"] = "1"                      # allows the built-in test secret key
os.environ["TRUSTVAULT_DB_URI"] = "sqlite:///" + os.path.join(_TMP, "test.db")
os.environ["TRUSTVAULT_UPLOAD_FOLDER"] = os.path.join(_TMP, "uploads")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import app as app_module  # noqa: E402
from models import db  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_app():
    """Empty database + empty upload folder + no remembered login failures, for every test."""
    flask_app = app_module.app
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False        # the CSRF test turns this back on
    with flask_app.app_context():
        db.session.remove()
        db.drop_all()
        app_module.init_database()
    app_module._login_failures.clear()
    upload_dir = flask_app.config["UPLOAD_FOLDER"]
    shutil.rmtree(upload_dir, ignore_errors=True)
    os.makedirs(upload_dir, exist_ok=True)
    yield flask_app


@pytest.fixture
def app(fresh_app):
    return fresh_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def make_client(app):
    """Gives you as many separate browsers as you like (one per person)."""
    return app.test_client
