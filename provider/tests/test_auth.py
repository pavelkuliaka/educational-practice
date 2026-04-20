import pytest


def test_login_get(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert b"<form" in response.data


def test_login_success(client, test_user):
    response = client.post(
        "/login",
        data={"email": test_user["email"], "password": test_user["password"]},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.location == "/dashboard"


def test_login_missing_fields(client):
    response = client.post(
        "/login",
        data={"email": "", "password": ""},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"<form" in response.data


def test_login_invalid_user(client):
    response = client.post(
        "/login",
        data={"email": "nonexistent@example.com", "password": "password"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"<form" in response.data


def test_login_invalid_password(client, test_user):
    response = client.post(
        "/login",
        data={"email": test_user["email"], "password": "wrongpassword"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"<form" in response.data


def test_login_with_next_url(client, test_user):
    response = client.post(
        "/login",
        data={
            "email": test_user["email"],
            "password": test_user["password"],
            "next": "/dashboard",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302


def test_logout(client):
    response = client.get("/logout", follow_redirects=False)
    assert response.status_code == 302
    assert response.location == "/login"


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.location


def test_dashboard_logged_in(logged_in_client):
    response = logged_in_client.get("/dashboard")
    assert response.status_code == 200
