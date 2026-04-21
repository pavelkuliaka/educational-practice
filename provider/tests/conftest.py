import os
import sys
import tempfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from werkzeug.security import generate_password_hash

test_dir = tempfile.mkdtemp()
key_path = os.path.join(test_dir, "test_key.pem")

private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
with open(key_path, "wb") as f:
    f.write(pem)

os.environ["PRIVATE_KEY_PATH"] = key_path
os.environ["APP_SECRET_KEY"] = "test-secret-key"


@pytest.fixture(scope="function")
def app():
    src_path = os.path.join(os.path.dirname(__file__), "..", "src")
    sys.path.insert(0, src_path)
    os.chdir(os.path.join(os.path.dirname(__file__), ".."))

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        os.environ["DATABASE_PATH"] = db_path

        if "src.config" in sys.modules:
            del sys.modules["src.config"]
        if "src.database" in sys.modules:
            del sys.modules["src.database"]

        from src.app import app as flask_app

        flask_app.config["TESTING"] = True
        flask_app.config["SECRET_KEY"] = "test-secret-key"

        with flask_app.app_context():
            from src.database import init_database

            init_database()

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

    create_user(email, generate_password_hash(password))
    return {"email": email, "password": password}


@pytest.fixture
def logged_in_client(client, test_user):
    with client.session_transaction() as sess:
        sess["user_email"] = test_user["email"]
    return client
