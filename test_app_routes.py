import pytest

from conftest import csrf_token


PROVIDERS = [
    "NVD",
    "MITRE",
    "OSV",
    "GitHub Advisory",
    "Red Hat Security Data",
    "CISA KEV",
]


def _seed_complete_record(application):
    successful_at = "2026-01-01T00:00:00+00:00"
    application.db.store_cve(
        {
            "id": "CVE-2026-1234",
            "description": "Cached vulnerability",
            "source": "NVD",
            "sources_checked": PROVIDERS,
            "provider_updates": PROVIDERS,
            "source_details": [
                {
                    "source": provider,
                    "status": "successful" if provider == "NVD" else "no_matching_record",
                    "last_checked_at": successful_at,
                }
                for provider in PROVIDERS
            ],
            "cvss_v3": {"score": 7.5, "severity": "HIGH"},
            "affected_systems": [
                {"product": "Widget", "source": "NVD", "status": "affected"}
            ],
            "refs": [
                {
                    "url": "https://example.test/advisory",
                    "source": "NVD",
                    "sources": ["NVD"],
                }
            ],
            "fetched_at": successful_at,
        }
    )


def test_refresh_is_post_only_public_and_csrf_protected(application):
    client = application.app.test_client()
    token = csrf_token(client)
    refresh_path = "/api/cve/CVE-2026-1234/refresh"

    get_response = client.get(refresh_path)
    assert get_response.status_code == 405

    missing_token_response = client.post(refresh_path)
    assert missing_token_response.status_code == 400

    application.nvd.fetch_cve = lambda cve_id: {
        "id": cve_id,
        "source": "NVD",
        "provider_updates": ["NVD"],
        "sources_checked": ["NVD"],
        "source_details": [{"source": "NVD", "status": "successful"}],
    }
    response = client.post(
        refresh_path,
        headers={"X-CSRFToken": token},
    )
    assert response.status_code == 200
    assert response.get_json()["cache"] == "REFRESHED"


def test_refresh_is_available_without_account_and_sync_remains_disabled(application):
    client = application.app.test_client()
    token = csrf_token(client)
    headers = {"X-CSRFToken": token}

    sync_response = client.post("/api/trigger-update", headers=headers)
    assert sync_response.status_code == 403
    assert sync_response.get_json() == {
        "error": "Manual feed synchronization is disabled."
    }


def test_cache_miss_get_is_read_only_and_post_fetches(application):
    client = application.app.test_client()
    token = csrf_token(client)
    calls = []

    def fetch(cve_id):
        calls.append(cve_id)
        return {
            "id": cve_id,
            "source": "NVD",
            "provider_updates": ["NVD"],
            "sources_checked": ["NVD"],
            "source_details": [{"source": "NVD", "status": "successful"}],
        }

    application.nvd.fetch_cve = fetch
    missing = client.get("/api/cve/CVE-2026-1234")
    assert missing.status_code == 404
    assert calls == []

    fetched = client.post(
        "/api/cve/CVE-2026-1234",
        headers={"X-CSRFToken": token},
    )
    assert fetched.status_code == 200
    assert fetched.get_json()["cache"] == "MISS"
    assert calls == ["CVE-2026-1234"]


def test_account_endpoints_are_removed(application):
    client = application.app.test_client()
    for path, method in (
        ("/api/register", "post"),
        ("/api/login", "post"),
        ("/api/logout", "post"),
        ("/api/auth/status", "get"),
    ):
        response = getattr(client, method)(path)
        assert response.status_code == 404


def test_stale_cache_records_provider_attempt_without_losing_success(application):
    successful_at = "2026-01-01T00:00:00+00:00"
    attempted_at = "2026-01-02T00:00:00+00:00"
    application.db.store_cve(
        {
            "id": "CVE-2026-1234",
            "source": "NVD",
            "provider_updates": ["NVD"],
            "sources_checked": ["NVD"],
            "source_details": [
                {
                    "source": "NVD",
                    "status": "successful",
                    "last_checked_at": successful_at,
                }
            ],
            "fetched_at": successful_at,
        }
    )
    application.nvd.cache_needs_refresh = lambda _cached: True

    def fail_refresh(_cve_id):
        raise application.CVEUpstreamError(
            "NVD is temporarily unavailable.",
            ["NVD"],
            {"NVD": "unavailable"},
            {"NVD": attempted_at},
        )

    client = application.app.test_client()
    token = csrf_token(client)
    application.nvd.fetch_cve = fail_refresh

    read_response = client.get("/api/cve/CVE-2026-1234")
    assert read_response.status_code == 200
    assert read_response.get_json()["cache"] == "STALE"
    detail = application.db.get_cve("CVE-2026-1234")["source_details"][0]
    assert detail["last_attempt_at"] == successful_at

    response = client.post(
        "/api/cve/CVE-2026-1234",
        headers={"X-CSRFToken": token},
    )

    assert response.status_code == 200
    assert response.get_json()["cache"] == "STALE"
    detail = application.db.get_cve("CVE-2026-1234")["source_details"][0]
    assert detail["last_attempt_at"] == attempted_at
    assert detail["last_attempt_outcome"] == "unavailable"
    assert detail["last_successful_retrieval_at"] == successful_at


@pytest.mark.parametrize("outcome", ["unavailable", "partial"])
def test_get_after_failed_or_partial_refresh_reports_retained_data_stale(
    application, outcome
):
    _seed_complete_record(application)
    client = application.app.test_client()
    token = csrf_token(client)
    attempted_at = "2026-01-02T00:00:00+00:00"
    cache_check = application.nvd.cache_needs_refresh
    application.nvd.cache_needs_refresh = lambda _cached: True

    def fail_refresh(_cve_id):
        raise application.CVEUpstreamError(
            f"NVD {outcome}.",
            ["NVD"],
            {"NVD": outcome},
            {"NVD": attempted_at},
        )

    application.nvd.fetch_cve = fail_refresh
    post_response = client.post(
        "/api/cve/CVE-2026-1234",
        headers={"X-CSRFToken": token},
    )
    assert post_response.status_code == 200
    assert post_response.get_json()["cache"] == "STALE"

    application.nvd.cache_needs_refresh = cache_check
    get_response = client.get("/api/cve/CVE-2026-1234")
    assert get_response.status_code == 200
    payload = get_response.get_json()
    assert payload["cache"] == "STALE"
    assert payload["data_warning"]
    assert payload["cvss_v3"]["score"] == 7.5


def test_get_after_no_record_refresh_reports_retained_data_stale(application):
    _seed_complete_record(application)
    client = application.app.test_client()
    token = csrf_token(client)
    cache_check = application.nvd.cache_needs_refresh
    application.nvd.cache_needs_refresh = lambda _cached: True
    application.nvd.fetch_cve = lambda _cve_id: None

    post_response = client.post(
        "/api/cve/CVE-2026-1234",
        headers={"X-CSRFToken": token},
    )
    assert post_response.status_code == 200
    assert post_response.get_json()["cache"] == "STALE"

    application.nvd.cache_needs_refresh = cache_check
    get_response = client.get("/api/cve/CVE-2026-1234")
    assert get_response.status_code == 200
    payload = get_response.get_json()
    assert payload["cache"] == "STALE"
    assert payload["data_warning"]
    assert payload["cvss_v3"]["score"] == 7.5
    assert payload["affected_systems"] == []


def test_successful_refresh_restores_fresh_cache_status(application):
    _seed_complete_record(application)
    client = application.app.test_client()
    token = csrf_token(client)
    cache_check = application.nvd.cache_needs_refresh
    application.nvd.cache_needs_refresh = lambda _cached: True
    application.nvd.fetch_cve = lambda _cve_id: None
    client.post(
        "/api/cve/CVE-2026-1234",
        headers={"X-CSRFToken": token},
    )

    recovered_at = "2026-01-03T00:00:00+00:00"
    application.nvd.fetch_cve = lambda cve_id: {
        "id": cve_id,
        "description": "Recovered vulnerability",
        "source": "NVD",
        "sources_checked": PROVIDERS,
        "provider_updates": PROVIDERS,
        "source_details": [
            {
                "source": provider,
                "status": "successful" if provider == "NVD" else "no_matching_record",
                "last_checked_at": recovered_at,
            }
            for provider in PROVIDERS
        ],
        "cvss_v3": {"score": 8.0, "severity": "HIGH"},
        "affected_systems": [
            {"product": "Widget", "source": "NVD", "status": "affected"}
        ],
        "refs": [],
        "source_warnings": [],
        "fetched_at": recovered_at,
    }

    recovered = client.post(
        "/api/cve/CVE-2026-1234",
        headers={"X-CSRFToken": token},
    )
    assert recovered.status_code == 200
    assert recovered.get_json()["cache"] == "REFRESHED"
    assert recovered.get_json()["source_warnings"] == []
    application.nvd.cache_needs_refresh = cache_check
    assert client.get("/api/cve/CVE-2026-1234").get_json()["cache"] == "HIT"


def test_uncached_mixed_provider_outcomes_are_returned_with_503(application):
    client = application.app.test_client()
    token = csrf_token(client)
    attempted_at = {
        provider: f"2026-01-02T00:00:0{index}+00:00"
        for index, provider in enumerate(PROVIDERS)
    }
    outcomes = {
        provider: "unavailable" if provider == "NVD" else "no_matching_record"
        for provider in PROVIDERS
    }

    def fail_fetch(_cve_id):
        raise application.CVEUpstreamError(
            "NVD could not be reached.",
            ["NVD"],
            outcomes,
            attempted_at,
        )

    application.nvd.fetch_cve = fail_fetch
    response = client.post(
        "/api/cve/CVE-2026-1234",
        headers={"X-CSRFToken": token},
    )

    assert response.status_code == 503
    payload = response.get_json()
    assert payload["provider_outcomes"] == outcomes
    details = {detail["source"]: detail for detail in payload["source_details"]}
    assert details["NVD"]["status"] == "unavailable"
    assert details["NVD"]["last_checked_at"] == attempted_at["NVD"]
    assert details["MITRE"]["status"] == "no_matching_record"
    assert details["MITRE"]["last_checked_at"] == attempted_at["MITRE"]
    assert payload["source_warnings"] == ["NVD could not be reached."]
    assert application.db.get_cve("CVE-2026-1234") is None


def test_poc_upstream_failure_returns_service_unavailable(application):
    client = application.app.test_client()

    def fail_fetch(_cve_id):
        raise application.CVEUpstreamError("Upstream unavailable.")

    application.nvd.fetch_cve = fail_fetch

    response = client.get("/api/cve/CVE-2026-1234/poc")

    assert response.status_code == 503
    assert response.get_json() == {"error": "Upstream unavailable."}
