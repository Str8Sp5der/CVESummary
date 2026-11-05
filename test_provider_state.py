from database import CVEDatabase


def _record(source, *, status="available", warning=None, score=7.5, advisory_id=None):
    detail = {
        "source": source,
        "trust_level": "authoritative",
        "untrusted": False,
        "status": status,
    }
    if advisory_id:
        detail["advisory_id"] = advisory_id
    data = {
        "id": "CVE-2024-0001",
        "description": "Test vulnerability",
        "source": source,
        "sources_checked": [source.split(" (", 1)[0]],
        "provider_updates": [source.split(" (", 1)[0]],
        "source_details": [detail],
        "source_warnings": [warning] if warning else [],
        "cvss_v3": {"score": score, "severity": "HIGH"},
        "affected_systems": [
            {
                "product": f"{source} product",
                "source": source,
                "status": "affected",
            }
        ],
        "refs": [
            {
                "url": f"https://example.test/{source}",
                "source": source,
                "sources": [source],
            }
        ],
        "fetched_at": "2024-01-03T01:00:00Z",
    }
    return data


def _database(tmp_path):
    return CVEDatabase(tmp_path / "provider_state.db")


def test_provider_updates_are_independent_of_order(tmp_path):
    first = _database(tmp_path / "first")
    second = _database(tmp_path / "second")

    for db, records in (
        (first, [_record("MITRE"), _record("NVD")]),
        (second, [_record("NVD"), _record("MITRE")]),
    ):
        for record in records:
            db.store_cve(record)

    first_state = first.get_cve("CVE-2024-0001")
    second_state = second.get_cve("CVE-2024-0001")
    assert first_state["sources_checked"] == second_state["sources_checked"]
    assert first_state["source_details"] == second_state["source_details"]
    assert first_state["source_warnings"] == second_state["source_warnings"]


def test_failed_refresh_preserves_successful_data_but_updates_current_status(tmp_path):
    db = _database(tmp_path)
    successful = _record("NVD")
    successful["source_records"] = [
        {
            "source": "NVD",
            "record_id": "CVE-2024-0001",
            "payload": {"score": 7.5},
        }
    ]
    db.store_cve(successful)

    failed = _record(
        "NVD",
        status="unavailable",
        warning="NVD could not be reached; its metadata may be missing.",
    )
    failed["fetched_at"] = "2024-01-04T01:00:00Z"
    failed["source_details"][0]["last_checked_at"] = failed["fetched_at"]
    failed.update(
        provider_updates=["NVD"],
        affected_systems=[],
        refs=[],
        source_records=[
            {
                "source": "NVD",
                "record_id": "retrieval-status",
                "payload": {
                    "retrieval_status": "unavailable",
                    "retrieved_at": "2024-01-03T01:00:00Z",
                },
                "claims": {"retrieval_status": "unavailable"},
                "review_status": "unavailable",
            }
        ],
    )
    db.store_cve(failed)

    stored = db.get_cve("CVE-2024-0001")
    assert stored["source_details"][0]["source"] == "NVD"
    assert stored["source_details"][0]["status"] == "unavailable"
    assert stored["source_details"][0]["last_attempt_at"] == failed["fetched_at"]
    assert (
        stored["source_details"][0]["last_successful_retrieval_at"]
        == successful["fetched_at"]
    )
    assert (
        stored["source_details"][0]["last_successful_payload_at"]
        == successful["fetched_at"]
    )
    assert stored["source_warnings"] == failed["source_warnings"]
    assert stored["affected_systems"] == successful["affected_systems"]
    assert stored["refs"] == successful["refs"]
    status_observation = next(
        observation
        for observation in stored["source_observations"]
        if observation["source_record_id"] == "retrieval-status"
    )
    assert status_observation["claims"]["retrieval_status"] == "unavailable"
    assert all(
        observation["source"] == "NVD"
        for observation in stored["source_observations"]
    )


def test_successful_refresh_clears_resolved_warning(tmp_path):
    db = _database(tmp_path)
    failed = _record(
        "NVD",
        status="unavailable",
        warning="NVD could not be reached; its metadata may be missing.",
    )
    db.store_cve(failed)

    recovered = _record("NVD")
    db.store_cve(recovered)

    stored = db.get_cve("CVE-2024-0001")
    assert stored["source_details"][0]["status"] == "successful"
    assert stored["source_warnings"] == []


def test_successful_no_record_replaces_provider_state_and_claims(tmp_path):
    db = _database(tmp_path)
    db.store_cve(_record("NVD"))

    no_record = {
        "id": "CVE-2024-0001",
        "source": "NVD",
        "sources_checked": ["NVD"],
        "provider_updates": ["NVD"],
        "source_details": [
            {"source": "NVD", "status": "no_matching_record"}
        ],
        "source_warnings": [],
        "affected_systems": [],
        "refs": [],
    }
    db.store_cve(no_record)

    stored = db.get_cve("CVE-2024-0001")
    detail = stored["source_details"][0]
    assert detail["source"] == "NVD"
    assert detail["status"] == "no_matching_record"
    assert detail["last_attempt_outcome"] == "no_matching_record"
    assert detail["last_successful_retrieval_at"]
    assert detail["last_successful_payload_at"] == "2024-01-03T01:00:00Z"
    assert stored["affected_systems"] == []
    assert stored["refs"] == []


def test_repeated_provider_updates_replace_status_and_deduplicate_advisories(tmp_path):
    db = _database(tmp_path)
    for status in ("unavailable", "available", "available"):
        update = {
            "id": "CVE-2024-0001",
            "source": "GitHub Advisory",
            "sources_checked": ["GitHub Advisory"],
            "provider_updates": ["GitHub Advisory"],
            "source_details": [
                {
                    "source": "GitHub Advisory (unreviewed)",
                    "advisory_id": "GHSA-1234",
                    "status": status,
                },
                {
                    "source": "GitHub Advisory (unreviewed)",
                    "advisory_id": "GHSA-1234",
                    "status": status,
                },
            ],
            "source_warnings": [],
        }
        db.store_cve(update)

    stored = db.get_cve("CVE-2024-0001")
    assert len(stored["source_details"]) == 1
    assert stored["source_details"][0]["source"] == "GitHub Advisory (unreviewed)"
    assert stored["source_details"][0]["status"] == "successful"
    assert stored["sources_checked"] == ["GitHub Advisory"]


def test_partial_provider_update_preserves_other_provider_and_missing_fields(tmp_path):
    db = _database(tmp_path)
    db.store_cve(_record("MITRE"))
    db.store_cve(
        {
            "id": "CVE-2024-0001",
            "source": "NVD",
            "sources_checked": ["NVD"],
            "provider_updates": ["NVD"],
            "source_details": [],
            "source_warnings": [],
        }
    )

    stored = db.get_cve("CVE-2024-0001")
    details = {detail["source"]: detail for detail in stored["source_details"]}
    assert details["MITRE"]["status"] == "successful"
    assert details["NVD"]["status"] == "partial"
    assert "MITRE" in stored["sources_checked"]
    assert "NVD" in stored["sources_checked"]
    assert stored["affected_systems"][0]["source"] == "MITRE"
    assert stored["refs"][0]["source"] == "MITRE"


def test_conflicting_provider_claims_remain_in_source_observation_history(tmp_path):
    db = _database(tmp_path)
    for source, score in (("MITRE", 7.1), ("NVD", 8.2)):
        record = _record(source, score=score)
        record["source_records"] = [
            {
                "source": source,
                "record_id": f"{source}-record",
                "claims": {"cvss_v3": {"score": score, "source": source}},
                "payload": {"score": score},
            }
        ]
        db.store_cve(record)

    stored = db.get_cve("CVE-2024-0001")
    claims = {
        observation["claims"]["cvss_v3"]["source"]:
        observation["claims"]["cvss_v3"]["score"]
        for observation in stored["source_observations"]
    }
    assert claims == {"MITRE": 7.1, "NVD": 8.2}
    assert {detail["source"] for detail in stored["source_details"]} == {
        "MITRE",
        "NVD",
    }
