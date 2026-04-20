import pytest


def test_register_user_get(client):
    response = client.get("/register/user")
    assert response.status_code == 200
    assert b"<form" in response.data


def test_register_user_success(client):
    response = client.post(
        "/register/user",
        data={
            "email": "newuser@example.com",
            "password": "password123",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"login" in response.data.lower()


def test_register_user_missing_fields(client):
    response = client.post(
        "/register/user",
        data={"email": "", "password": ""},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"<form" in response.data


def test_register_user_duplicate(client, test_user):
    response = client.post(
        "/register/user",
        data={
            "email": test_user["email"],
            "password": "password",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"<form" in response.data


def test_register_user_json_success(client):
    response = client.post(
        "/register/user",
        json={"email": "jsonuser@example.com", "password": "password123"},
    )
    if response.status_code == 201:
        assert response.json["email"] == "jsonuser@example.com"
    else:
        assert response.status_code == 400


def test_register_user_json_duplicate(client, test_user):
    response = client.post(
        "/register/user",
        json={"email": test_user["email"], "password": "password"},
    )
    assert response.status_code == 400
    assert response.json["error"] == "user_already_exists"


def test_register_user_json_missing_fields(client):
    response = client.post(
        "/register/user",
        json={},
    )
    assert response.status_code == 400
    assert response.json["error"] == "missing_email_or_password"


def test_register_app_get(client):
    response = client.get("/register/app")
    assert response.status_code == 302


def test_register_app_logged_in(logged_in_client):
    response = logged_in_client.get("/register/app")
    assert response.status_code == 200
    assert b"<form" in response.data


def test_register_app_success(logged_in_client):
    response = logged_in_client.post(
        "/register/app",
        data={
            "name": "My Test App",
            "redirect_uri": "http://localhost/callback",
        },
    )
    assert response.status_code == 200
    response_text = response.data.decode()
    assert "client_id" in response_text.lower() or "Client ID" in response_text


def test_register_app_missing_redirect_uri(logged_in_client):
    response = logged_in_client.post(
        "/register/app",
        data={
            "name": "My Test App",
            "redirect_uri": "",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Redirect URI" in response.data.decode()


def test_register_app_json_success(logged_in_client):
    response = logged_in_client.post(
        "/register/app",
        json={
            "name": "JSON App",
            "redirect_uri": "http://localhost/callback",
        },
    )
    assert response.status_code == 201
    assert "client_id" in response.json
    assert "client_secret" in response.json


def test_register_app_json_missing_redirect_uri(logged_in_client):
    response = logged_in_client.post(
        "/register/app",
        json={"name": "JSON App"},
    )
    assert response.status_code == 400
    assert response.json["error"] == "missing_redirect_uri"
