from conftest import csrf_token


def test_registration_login_and_logout_use_csrf_and_sessions(application):
    client = application.app.test_client()
    token = csrf_token(client)
    headers = {"X-CSRFToken": token}
    credentials = {
        "username": "stable-user",
        "password": "StablePass123!",
    }

    assert client.post("/api/register", json=credentials).status_code == 400
    registration = client.post(
        "/api/register",
        json=credentials,
        headers=headers,
    )
    assert registration.status_code == 201

    stored_user = application.db.get_user(credentials["username"])
    assert stored_user
    assert stored_user["password_hash"] != credentials["password"]

    login = client.post(
        "/api/login",
        json=credentials,
        headers=headers,
    )
    assert login.status_code == 200
    assert client.get("/api/auth/status").get_json() == {
        "authenticated": True,
        "username": credentials["username"],
    }

    logout = client.post("/api/logout", headers=headers)
    assert logout.status_code == 200
    assert client.get("/api/auth/status").get_json() == {"authenticated": False}


def test_invalid_credentials_do_not_create_authenticated_session(application):
    client = application.app.test_client()
    token = csrf_token(client)

    response = client.post(
        "/api/login",
        json={"username": "missing-user", "password": "StablePass123!"},
        headers={"X-CSRFToken": token},
    )

    assert response.status_code == 401
    assert client.get("/api/auth/status").get_json() == {"authenticated": False}
