import os
import sys
import tempfile
from unittest.mock import patch, MagicMock

import pytest
from werkzeug.security import generate_password_hash


@pytest.fixture(scope="function")
def app():
    src_path = os.path.join(os.path.dirname(__file__), "..", "src")
    os.chdir(os.path.join(os.path.dirname(__file__), ".."))

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        os.environ["DATABASE_PATH"] = db_path
        os.environ["APP_SECRET_KEY"] = "test-secret-key"
        os.environ["REDIRECT_URI"] = "http://localhost/callback"
        os.environ["GOOGLE_CLIENT_ID"] = "test-google-id"
        os.environ["GOOGLE_CLIENT_SECRET"] = "test-google-secret"
        os.environ["GITHUB_CLIENT_ID"] = "test-github-id"
        os.environ["GITHUB_CLIENT_SECRET"] = "test-github-secret"
        os.environ["YANDEX_CLIENT_ID"] = "test-yandex-id"
        os.environ["YANDEX_CLIENT_SECRET"] = "test-yandex-secret"
        os.environ["MY_SERVICE_CLIENT_ID"] = "test-service-id"
        os.environ["MY_SERVICE_CLIENT_SECRET"] = "test-service-secret"

        # Очищаем модули
        for mod in list(sys.modules.keys()):
            if mod.startswith("src."):
                del sys.modules[mod]

        sys.path.insert(0, src_path)

        # Мокаем connect до импорта src
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        with patch("sqlite3.connect", return_value=mock_conn):
            from src.app import app as flask_app
            from src.database import init_database

            init_database()

            flask_app.config["TESTING"] = True
            flask_app.config["SECRET_KEY"] = "test-secret-key"

            yield flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def app_context(app):
    with app.app_context():
        yield


@pytest.fixture
def test_user(app_context):
    from src.database import create_user
    import uuid

    email = f"test-{uuid.uuid4().hex[:8]}@example.com"
    password = "testpassword"

    create_user(email, generate_password_hash(password), None)
    return {"email": email, "password": password}


@pytest.fixture
def logged_in_client(client, test_user):
    with client.session_transaction() as sess:
        sess["user_email"] = test_user["email"]
    return client
