def test_poc_route_is_public_and_returns_cached_data(application):
    client = application.app.test_client()
    application.db.store_cve(
        {
            "id": "CVE-2021-44228",
            "poc": [{"title": "Cached reference", "url": "https://example.test/poc"}],
        }
    )

    response = client.get("/api/cve/CVE-2021-44228/poc")

    assert response.status_code == 200
    assert response.get_json() == {
        "cve_id": "CVE-2021-44228",
        "poc": [{"title": "Cached reference", "url": "https://example.test/poc"}],
    }
