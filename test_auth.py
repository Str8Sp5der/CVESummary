def test_account_endpoints_are_not_registered(application):
    client = application.app.test_client()

    assert client.post("/api/register").status_code == 404
    assert client.post("/api/login").status_code == 404
    assert client.post("/api/logout").status_code == 404
    assert client.get("/api/auth/status").status_code == 404
