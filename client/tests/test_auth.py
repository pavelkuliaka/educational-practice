

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


def test_login_invalid_user(client):
    response = client.post(
        "/login",
        data={"email": "nonexistent@example.com", "password": "password"},
        follow_redirects=True,
    )
    assert response.status_code == 200


def test_login_invalid_password(client, test_user):
    response = client.post(
        "/login",
        data={"email": test_user["email"], "password": "wrongpassword"},
        follow_redirects=True,
    )
    assert response.status_code == 200


def test_login_already_logged_in(client, logged_in_client):
    response = logged_in_client.get("/login")
    assert response.status_code == 302
    assert response.location == "/dashboard"


def test_login_provider_not_found(client):
    response = client.get("/login/invalid_provider")
    assert response.status_code == 404


def test_register_get(client):
    response = client.get("/register")
    assert response.status_code == 200
    assert b"<form" in response.data


def test_register_success(client):
    response = client.post(
        "/register",
        data={
            "email": "newuser@example.com",
            "password": "newpassword",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"login" in response.data.lower()


def test_register_duplicate(client, test_user):
    response = client.post(
        "/register",
        data={
            "email": test_user["email"],
            "password": "password",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"<form" in response.data


def test_register_already_logged_in(client, logged_in_client):
    response = logged_in_client.get("/register")
    assert response.status_code == 302
    assert response.location == "/dashboard"


def test_home_logged_in(client, logged_in_client):
    response = logged_in_client.get("/")
    assert response.status_code == 302
    assert response.location == "/dashboard"


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
