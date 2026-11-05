from conftest import authenticate, csrf_token


def test_poc_route_requires_authentication_and_uses_cached_data(application):
    client = application.app.test_client()
    token = csrf_token(client)
    application.db.store_cve(
        {
            "id": "CVE-2021-44228",
            "poc": [{"title": "Cached reference", "url": "https://example.test/poc"}],
        }
    )

    anonymous = client.get("/api/cve/CVE-2021-44228/poc")
    assert anonymous.status_code == 401

    authenticate(application, client, "poc-user")
    response = client.get("/api/cve/CVE-2021-44228/poc")
    assert response.status_code == 200
    assert response.get_json()["accessed_by"] == "poc-user"
    assert response.get_json()["poc"][0]["title"] == "Cached reference"

    assert client.post("/api/logout", headers={"X-CSRFToken": token}).status_code == 200
    assert client.get("/api/cve/CVE-2021-44228/poc").status_code == 401
