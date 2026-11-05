from conftest import csrf_token


def test_auth_endpoints_reject_invalid_input_and_require_csrf(application):
    client = application.app.test_client()
    token = csrf_token(client)

    missing_token = client.post(
        "/api/register",
        json={"username": "valid-user", "password": "StablePass123!"},
    )
    assert missing_token.status_code == 400

    invalid_username = client.post(
        "/api/login",
        json={
            "username": "admin' OR '1'='1",
            "password": "StablePass123!",
        },
        headers={"X-CSRFToken": token},
    )
    assert invalid_username.status_code == 400

    status = client.get("/api/auth/status")
    assert status.status_code == 200
    assert status.get_json() == {"authenticated": False}
