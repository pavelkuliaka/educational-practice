import os
import sys
from datetime import datetime, timedelta

import pytest
from src.database import (
    create_access_token,
    create_app,
    create_auth_code,
)

src_path = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, src_path)


@pytest.fixture
def test_app(app_context):
    import secrets

    client_id = secrets.token_hex(16)
    client_secret = secrets.token_hex(32)

    create_app(
        client_id,
        client_secret,
        "Test App",
        "http://localhost/callback",
        "test@example.com",
    )

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": "http://localhost/callback",
    }


def test_openid_config(client):
    response = client.get("/oauth/.well-known/openid-configuration")
    assert response.status_code == 200

    data = response.json
    assert data["issuer"] == "http://localhost:5001/oauth"
    assert "authorization_endpoint" in data
    assert "token_endpoint" in data
    assert "jwks_uri" in data


def test_authorize_missing_state(client, test_app):
    response = client.get(
        f"/oauth/authorize?client_id={test_app['client_id']}&redirect_uri={test_app['redirect_uri']}&scope=openid&response_type=code"
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request"


def test_authorize_invalid_scope(client, test_app):
    response = client.get(
        f"/oauth/authorize?client_id={test_app['client_id']}&redirect_uri={test_app['redirect_uri']}&scope=invalid_scope&response_type=code&state=xyz"
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_scope"


def test_authorize_missing_scope(client, test_app):
    response = client.get(
        f"/oauth/authorize?client_id={test_app['client_id']}&redirect_uri={test_app['redirect_uri']}&response_type=code&state=xyz"
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_scope"


def test_authorize_invalid_client(client):
    response = client.get(
        "/oauth/authorize?client_id=invalid&redirect_uri=http://localhost/callback&scope=openid&response_type=code&state=xyz"
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_client"


def test_authorize_invalid_redirect_uri(client, test_app):
    response = client.get(
        f"/oauth/authorize?client_id={test_app['client_id']}&redirect_uri=http://evil.com/callback&scope=openid&response_type=code&state=xyz"
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_redirect_uri"


def test_authorize_unsupported_response_type(client, test_app):
    response = client.get(
        f"/oauth/authorize?client_id={test_app['client_id']}&redirect_uri={test_app['redirect_uri']}&scope=openid&response_type=token&state=xyz"
    )
    assert response.status_code == 400
    assert response.json["error"] == "unsupported_response_type"


def test_token_missing_grant_type(client):
    response = client.post("/oauth/token")
    assert response.status_code == 400
    assert response.json["error"] == "unsupported_grant_type"


def test_token_missing_parameters(client, test_app):
    response = client.post(
        "/oauth/token",
        data={"grant_type": "authorization_code"},
    )
    assert response.status_code == 401


def test_token_invalid_client(client):
    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": "testcode",
            "client_id": "invalid",
            "client_secret": "invalid",
            "redirect_uri": "http://localhost/callback",
        },
    )
    assert response.status_code == 401
    assert response.json["error"] == "invalid_client"


def test_token_invalid_grant(client, test_app):
    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": "invalidcode",
            "client_id": test_app["client_id"],
            "client_secret": test_app["client_secret"],
            "redirect_uri": test_app["redirect_uri"],
        },
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_grant"


def test_token_expired_code(client, test_app, app_context):
    import uuid

    code = f"expiredcode-{uuid.uuid4().hex[:8]}"
    create_auth_code(
        code,
        test_app["client_id"],
        "user123",
        "test@example.com",
        (datetime.now() - timedelta(minutes=1)).isoformat(),
        None,
        None,
        None,
        "openid",
    )

    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": test_app["client_id"],
            "client_secret": test_app["client_secret"],
            "redirect_uri": test_app["redirect_uri"],
        },
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_grant"


def test_token_success(client, test_app, app_context):
    import uuid

    code = f"validcode-{uuid.uuid4().hex[:8]}"
    create_auth_code(
        code,
        test_app["client_id"],
        "user123",
        "test@example.com",
        (datetime.now() + timedelta(minutes=10)).isoformat(),
        None,
        None,
        None,
        "openid",
    )

    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": test_app["client_id"],
            "client_secret": test_app["client_secret"],
            "redirect_uri": test_app["redirect_uri"],
        },
    )
    assert response.status_code == 200
    data = response.json
    assert "access_token" in data
    assert data["token_type"] == "Bearer"
    assert "id_token" in data


def test_token_with_pkce(client, test_app, app_context):
    import uuid

    code = f"pkcecode-{uuid.uuid4().hex[:8]}"
    code_challenge = "test_challenge"
    create_auth_code(
        code,
        test_app["client_id"],
        "user123",
        "test@example.com",
        (datetime.now() + timedelta(minutes=10)).isoformat(),
        None,
        code_challenge,
        "plain",
        "openid",
    )

    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": test_app["client_id"],
            "client_secret": test_app["client_secret"],
            "redirect_uri": test_app["redirect_uri"],
            "code_verifier": "test_challenge",
        },
    )
    assert response.status_code == 200


def test_token_with_invalid_pkce(client, test_app, app_context):
    import uuid

    code = f"badpkce-{uuid.uuid4().hex[:8]}"
    code_challenge = "test_challenge"
    create_auth_code(
        code,
        test_app["client_id"],
        "user123",
        "test@example.com",
        (datetime.now() + timedelta(minutes=10)).isoformat(),
        None,
        code_challenge,
        "plain",
        "openid",
    )

    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": test_app["client_id"],
            "client_secret": test_app["client_secret"],
            "redirect_uri": test_app["redirect_uri"],
            "code_verifier": "wrong_verifier",
        },
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_grant"


def test_userinfo_no_token(client):
    response = client.get("/oauth/userinfo")
    assert response.status_code == 401
    assert response.json["error"] == "unauthorized"


def test_userinfo_invalid_token(client):
    response = client.get(
        "/oauth/userinfo",
        headers={"Authorization": "Bearer invalidtoken"},
    )
    assert response.status_code == 401
    assert response.json["error"] == "invalid_token"


def test_userinfo_expired_token(client, app_context):
    import uuid

    token = f"expiredtoken-{uuid.uuid4().hex[:8]}"
    create_access_token(
        token,
        "user123",
        "test@example.com",
        "openid email",
        (datetime.now() - timedelta(minutes=1)).isoformat(),
    )

    response = client.get(
        "/oauth/userinfo",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert response.json["error"] == "invalid_token"


def test_userinfo_success(client, app_context):
    import uuid

    token = f"validtoken-{uuid.uuid4().hex[:8]}"
    create_access_token(
        token,
        "user123",
        "test@example.com",
        "openid email",
        (datetime.now() + timedelta(hours=1)).isoformat(),
    )

    response = client.get(
        "/oauth/userinfo",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json
    assert data["sub"] == "user123"
    assert data["email"] == "test@example.com"
    assert data["email_verified"] is True


def test_jwks(client):
    response = client.get("/oauth/jwks.json")
    assert response.status_code == 200

    data = response.json
    assert "keys" in data
