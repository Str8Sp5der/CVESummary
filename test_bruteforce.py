from conftest import csrf_token


def test_login_is_locked_after_five_failed_attempts(application):
    client = application.app.test_client()
    token = csrf_token(client)
    headers = {"X-CSRFToken": token}
    credentials = {
        "username": "locked-user",
        "password": "StablePass123!",
    }

    registration = client.post(
        "/api/register",
        json=credentials,
        headers=headers,
    )
    assert registration.status_code == 201

    for _ in range(5):
        response = client.post(
            "/api/login",
            json={
                "username": credentials["username"],
                "password": "WrongPass123!",
            },
            headers=headers,
        )
        assert response.status_code == 401

    locked = client.post(
        "/api/login",
        json=credentials,
        headers=headers,
    )
    assert locked.status_code == 429
