import pytest
import secrets
import os
import sys

src_path = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, src_path)


@pytest.fixture
def owned_app(logged_in_client, test_user, app_context):
    from src.database import create_app

    client_id = secrets.token_hex(16)
    client_secret = secrets.token_hex(32)

    create_app(
        client_id,
        client_secret,
        "Owned App",
        "http://localhost/callback",
        test_user["email"],
    )

    return {
        "client_id": client_id,
        "client_secret": client_secret,
    }


@pytest.fixture
def client_for_delete(app):
    return app.test_client()


def test_delete_app_requires_login(client_for_delete, owned_app):
    response = client_for_delete.post(f"/app/{owned_app['client_id']}/delete")
    assert response.status_code in [200, 302]


@pytest.fixture
def client_for_regenerate(app):
    return app.test_client()


def test_regenerate_secret_requires_login(client_for_regenerate, owned_app):
    response = client_for_regenerate.post(f"/app/{owned_app['client_id']}/regenerate")
    assert response.status_code in [200, 302]


def test_delete_app_success(logged_in_client, owned_app):
    response = logged_in_client.post(
        f"/app/{owned_app['client_id']}/delete",
        follow_redirects=True,
    )
    assert response.status_code == 200


def test_regenerate_secret_success(logged_in_client, owned_app):
    old_secret = owned_app["client_secret"]

    response = logged_in_client.post(
        f"/app/{owned_app['client_id']}/regenerate",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert owned_app["client_id"].encode() in response.data
    assert old_secret.encode() not in response.data
