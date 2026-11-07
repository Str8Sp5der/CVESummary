import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from database import CVEDatabase
from nvd_client import (
    CISA_KEV_FEED,
    CISAKEVUpdateError,
    CVELISTV5_RAW,
    MITRE_CVE_API,
    NVD_API,
    OSV_API,
    REDHAT_CVE_API,
    CVEUpstreamError,
    NVDClient,
    NVDUpdateError,
)


def nvd_record(cve_id: str) -> dict:
    cpe_matches = [
        {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
            "versionStartIncluding": "1.0",
            "versionEndExcluding": "2.0",
        }
    ] + [
        {
            "vulnerable": True,
            "criteria": f"cpe:2.3:a:vendor{index}:product{index}:*:*:*:*:*:*:*:*",
        }
        for index in range(40)
    ]
    return {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": "A test vulnerability."}],
        "published": "2026-01-01T00:00:00.000",
        "lastModified": "2026-01-02T00:00:00.000",
        "metrics": {},
        "configurations": [
            {
                "nodes": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": cpe_matches
                            }
                        ]
                    }
                ]
            }
        ],
        "references": [],
        "weaknesses": [],
    }


def cvelistv5_record(cve_id: str) -> dict:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {
            "cveId": cve_id,
            "state": "PUBLISHED",
            "datePublished": "2026-01-01T00:00:00Z",
            "dateUpdated": "2026-01-02T00:00:00Z",
        },
        "containers": {
            "cna": {
                "descriptions": [
                    {"lang": "en", "value": "A cvelistV5 vulnerability."}
                ],
                "affected": [
                    {
                        "vendor": "Acme",
                        "product": "Widget",
                        "versions": [
                            {
                                "version": "1.0",
                                "lessThan": "2.0",
                                "status": "affected",
                            }
                        ],
                    }
                ],
                "references": [
                    {"url": "https://example.test/advisory", "name": "Advisory"}
                ],
            },
            "adp": [],
        },
    }


def response(payload: object) -> Mock:
    result = Mock()
    result.json.return_value = payload
    result.raise_for_status.return_value = None
    return result


def not_found_response() -> Mock:
    result = Mock()
    error = requests.HTTPError("not found")
    error.response = Mock(status_code=404)
    result.raise_for_status.side_effect = error
    return result


class NVDClientTests(unittest.TestCase):
    def test_fetches_from_nvd_using_the_cve_filter_and_api_key(self):
        client = NVDClient(api_key="test-key")
        client.session.get = Mock(
            side_effect=[
                response(
                    {"vulnerabilities": [{"cve": nvd_record("CVE-2026-1234")}]}
                ),
                not_found_response(),
                response({}),
                response([]),
            ]
        )
        with patch.object(client, "_collect_poc", return_value=[]), patch.object(
            client, "_fetch_redhat_cve", return_value=None
        ), patch.object(client, "_fetch_cisa_kev", return_value=None):
            cve = client.fetch_cve("CVE-2026-1234")

        self.assertEqual(cve["source"], "NVD")
        self.assertEqual(cve["id"], "CVE-2026-1234")
        self.assertEqual(
            cve["affected_systems"][0]["version_end"],
            "2.0",
        )
        self.assertEqual(len(cve["affected_systems"]), 41)
        self.assertEqual(cve["affected_systems"][0]["version_range"], ">= 1.0, < 2.0")
        self.assertEqual(client.session.get.call_count, 4)
        args, kwargs = client.session.get.call_args_list[0]
        self.assertEqual(args[0], NVD_API)
        self.assertEqual(kwargs["params"], {"cveId": "CVE-2026-1234"})
        self.assertEqual(kwargs["headers"], {"apiKey": "test-key"})

    def test_fetch_records_successful_no_record_provider_outcomes(self):
        client = NVDClient()
        client.session.get = Mock(
            return_value=response(
                {"vulnerabilities": [{"cve": nvd_record("CVE-2026-1234")}]}
            )
        )
        with patch.object(client, "_fetch_mitre_cve", return_value=None), patch.object(
            client, "_fetch_cvelistv5_cve", return_value=None
        ) as cvelist_fallback, patch.object(
            client, "_fetch_osv_cve", return_value=None
        ), patch.object(client, "_fetch_github_advisory", return_value=None), patch.object(
            client, "_fetch_redhat_cve", return_value=None
        ), patch.object(client, "_fetch_cisa_kev", return_value=None), patch.object(
            client, "_collect_poc", return_value=[]
        ):
            cve = client.fetch_cve("CVE-2026-1234")

        retrieval_outcomes = {
            record["source"]: record["claims"]["retrieval_status"]
            for record in cve["source_records"]
            if record["record_id"] == "retrieval-status"
        }
        self.assertEqual(
            retrieval_outcomes,
            {
                "MITRE": "no_matching_record",
                "OSV": "no_matching_record",
                "GitHub Advisory": "no_matching_record",
                "Red Hat Security Data": "no_matching_record",
                "CISA KEV": "no_matching_record",
            },
        )
        cvelist_fallback.assert_called_once_with("CVE-2026-1234")

    def test_falls_back_to_cvelistv5_when_mitre_api_has_no_record(self):
        client = NVDClient()
        client.session.get = Mock(
            return_value=response(
                {"vulnerabilities": [{"cve": nvd_record("CVE-2026-1234")}]}
            )
        )
        with patch.object(client, "_fetch_mitre_cve", return_value=None), patch.object(
            client,
            "_fetch_cvelistv5_cve",
            return_value=cvelistv5_record("CVE-2026-1234"),
        ) as cvelist_fallback, patch.object(
            client, "_fetch_osv_cve", return_value=None
        ), patch.object(client, "_fetch_github_advisory", return_value=None), patch.object(
            client, "_fetch_redhat_cve", return_value=None
        ), patch.object(client, "_fetch_cisa_kev", return_value=None), patch.object(
            client, "_collect_poc", return_value=[]
        ):
            cve = client.fetch_cve("CVE-2026-1234")

        cvelist_fallback.assert_called_once_with("CVE-2026-1234")
        self.assertEqual(cve["description"], "A test vulnerability.")
        self.assertEqual(
            next(
                detail
                for detail in cve["source_details"]
                if detail["source"] == "MITRE/CNA"
            )["status"],
            "successful",
        )
        self.assertNotIn("MITRE", cve["source_warnings"])

    def test_merge_uses_mitre_description_when_nvd_description_is_empty(self):
        nvd = {
            "id": "CVE-2026-1234",
            "description": "",
            "source": "NVD",
            "affected_systems": [],
            "refs": [],
            "cwes": [],
        }
        mitre = {
            "id": "CVE-2026-1234",
            "description": "Description supplied by the CNA.",
            "source": "MITRE",
            "affected_systems": [],
            "refs": [],
            "cwes": [],
        }

        merged = NVDClient._merge_records(nvd, mitre)

        self.assertEqual(merged["description"], "Description supplied by the CNA.")

    def test_upstream_error_tracks_each_provider_attempt_time(self):
        client = NVDClient()
        client.session.get = Mock(side_effect=requests.Timeout("upstream timeout"))
        with patch.object(client, "_fetch_mitre_cve", return_value=None), patch.object(
            client, "_fetch_osv_cve", return_value=None
        ), patch.object(client, "_fetch_github_advisory", return_value=None), patch.object(
            client, "_fetch_redhat_cve", return_value=None
        ), patch.object(client, "_fetch_cisa_kev", return_value=None):
            with self.assertRaises(CVEUpstreamError) as raised:
                client.fetch_cve("CVE-2026-1234")

        self.assertEqual(
            set(raised.exception.attempted_at),
            {
                "NVD",
                "MITRE",
                "OSV",
                "GitHub Advisory",
                "Red Hat Security Data",
                "CISA KEV",
            },
        )
        for timestamp in raised.exception.attempted_at.values():
            datetime.fromisoformat(timestamp)

    def test_falls_back_to_mitre_when_nvd_has_no_matching_record(self):
        client = NVDClient()
        client.session.get = Mock(
            side_effect=[
                response({"vulnerabilities": []}),
                response(
                    {
                        "cveMetadata": {
                            "cveId": "CVE-2026-1234",
                            "datePublished": "2026-01-01T00:00:00Z",
                        },
                        "containers": {
                            "cna": {
                                "descriptions": [
                                    {"lang": "en", "value": "MITRE fallback record."}
                                ]
                            }
                        },
                    }
                ),
                response({}),
                response(
                    [
                        {
                            "ghsa_id": "GHSA-1111",
                            "cve_id": "CVE-2026-1234",
                            "type": "reviewed",
                            "vulnerabilities": [],
                        },
                        {
                            "ghsa_id": "GHSA-2222",
                            "cve_id": "CVE-2026-1234",
                            "type": "reviewed",
                            "vulnerabilities": [],
                        },
                    ]
                ),
            ]
        )
        with patch.object(client, "_collect_poc", return_value=[]), patch.object(
            client, "_fetch_redhat_cve", return_value=None
        ), patch.object(client, "_fetch_cisa_kev", return_value=None):
            cve = client.fetch_cve("CVE-2026-1234")

        self.assertEqual(cve["source"], "MITRE + GitHub Advisory")
        self.assertEqual(cve["description"], "MITRE fallback record.")
        self.assertEqual(
            client.session.get.call_args_list[1].args[0],
            f"{MITRE_CVE_API}/CVE-2026-1234",
        )
        self.assertEqual(
            client.session.get.call_args_list[2].args[0],
            f"{OSV_API}/CVE-2026-1234",
        )
        self.assertEqual(
            cve["sources_checked"],
            [
                "NVD",
                "MITRE",
                "OSV",
                "GitHub Advisory",
                "Red Hat Security Data",
                "CISA KEV",
            ],
        )
        self.assertEqual(
            {
                detail["advisory_id"]
                for detail in cve["source_details"]
                if detail.get("advisory_id")
            },
            {"GHSA-1111", "GHSA-2222"},
        )
        self.assertEqual(
            {
                record["source"]
                for record in cve["source_records"]
                if record["record_id"] != "retrieval-status"
            },
            {"MITRE", "GitHub Advisory"},
        )
        self.assertEqual(
            {
                record["source"]: record["claims"]["retrieval_status"]
                for record in cve["source_records"]
                if record["record_id"] == "retrieval-status"
            },
            {
                "NVD": "no_matching_record",
                "OSV": "no_matching_record",
                "Red Hat Security Data": "no_matching_record",
                "CISA KEV": "no_matching_record",
            },
        )
        self.assertTrue(
            all(detail.get("last_checked_at") for detail in cve["source_details"])
        )

    def test_fetches_and_parses_cvelistv5_record(self):
        client = NVDClient()
        client.session.get = Mock(
            return_value=response(cvelistv5_record("CVE-2026-1234"))
        )

        record = client._fetch_cvelistv5_cve("CVE-2026-1234")

        self.assertEqual(
            client.session.get.call_args.args[0],
            CVELISTV5_RAW.format(
                year="2026",
                bucket="1xxx",
                cve_id="CVE-2026-1234",
            ),
        )
        self.assertEqual(record["description"], "A cvelistV5 vulnerability.")
        self.assertEqual(
            record["affected_systems"][0]["version_range"],
            ">= 1.0, < 2.0",
        )
        self.assertEqual(record["refs"][0]["sources"], ["MITRE"])
        self.assertEqual(
            record["source_details"][0]["retrieval_path"],
            "CVEProject/cvelistV5",
        )
        self.assertEqual(
            record["source_records"][0]["claims"]["retrieval_path"],
            "CVEProject/cvelistV5",
        )

    def test_cvelistv5_rejects_malformed_and_mismatched_records(self):
        client = NVDClient()
        client.session.get = Mock(
            side_effect=[
                response({"dataType": "CVE_RECORD", "containers": {}}),
                response(cvelistv5_record("CVE-2026-5678")),
            ]
        )

        with self.assertRaisesRegex(ValueError, "malformed"):
            client._fetch_cvelistv5_cve("CVE-2026-1234")
        with self.assertRaisesRegex(ValueError, "different CVE ID"):
            client._fetch_cvelistv5_cve("CVE-2026-1234")

    def test_cvelistv5_404_is_a_no_record_response(self):
        client = NVDClient()
        missing = Mock()
        not_found = requests.HTTPError("not found")
        not_found.response = Mock(status_code=404)
        missing.raise_for_status.side_effect = not_found
        client.session.get = Mock(return_value=missing)

        self.assertIsNone(client._fetch_cvelistv5_cve("CVE-2026-1234"))

    def test_uses_cvelistv5_only_after_mitre_api_error(self):
        client = NVDClient()
        client.session.get = Mock(
            side_effect=[
                response({"vulnerabilities": []}),
                response(cvelistv5_record("CVE-2026-1234")),
            ]
        )
        with patch.object(
            client, "_fetch_mitre_cve", side_effect=requests.Timeout("MITRE timeout")
        ), patch.object(client, "_fetch_osv_cve", return_value=None), patch.object(
            client, "_fetch_github_advisory", return_value=None
        ), patch.object(client, "_fetch_redhat_cve", return_value=None), patch.object(
            client, "_fetch_cisa_kev", return_value=None
        ), patch.object(client, "_collect_poc", return_value=[]):
            cve = client.fetch_cve("CVE-2026-1234")

        self.assertEqual(
            client.session.get.call_args_list[1].args[0],
            CVELISTV5_RAW.format(
                year="2026",
                bucket="1xxx",
                cve_id="CVE-2026-1234",
            ),
        )
        mitre_detail = next(
            detail for detail in cve["source_details"] if detail["source"] == "MITRE/CNA"
        )
        self.assertEqual(mitre_detail["status"], "successful")
        self.assertEqual(mitre_detail["retrieval_path"], "CVEProject/cvelistV5")
        self.assertNotIn("MITRE", cve["source_warnings"])

    def test_failed_cvelistv5_fallback_keeps_mitre_outcome_partial(self):
        client = NVDClient()
        client.session.get = Mock(
            return_value=response(
                {"vulnerabilities": [{"cve": nvd_record("CVE-2026-1234")}]}
            )
        )
        with patch.object(
            client, "_fetch_mitre_cve", side_effect=requests.Timeout("MITRE timeout")
        ), patch.object(
            client,
            "_fetch_cvelistv5_cve",
            side_effect=ValueError("Malformed CVE record."),
        ), patch.object(client, "_fetch_osv_cve", return_value=None), patch.object(
            client, "_fetch_github_advisory", return_value=None
        ), patch.object(client, "_fetch_redhat_cve", return_value=None), patch.object(
            client, "_fetch_cisa_kev", return_value=None
        ), patch.object(client, "_collect_poc", return_value=[]):
            cve = client.fetch_cve("CVE-2026-1234")

        mitre_detail = next(
            detail for detail in cve["source_details"] if detail["source"] == "MITRE"
        )
        self.assertEqual(mitre_detail["status"], "partial")
        self.assertTrue(
            any(warning.startswith("MITRE returned incomplete data") for warning in cve["source_warnings"])
        )

    def test_cvelistv5_not_found_after_mitre_error_is_unavailable(self):
        client = NVDClient()
        client.session.get = Mock(
            return_value=response(
                {"vulnerabilities": [{"cve": nvd_record("CVE-2026-1234")}]}
            )
        )
        with patch.object(
            client, "_fetch_mitre_cve", side_effect=requests.Timeout("MITRE timeout")
        ), patch.object(
            client, "_fetch_cvelistv5_cve", return_value=None
        ), patch.object(client, "_fetch_osv_cve", return_value=None), patch.object(
            client, "_fetch_github_advisory", return_value=None
        ), patch.object(client, "_fetch_redhat_cve", return_value=None), patch.object(
            client, "_fetch_cisa_kev", return_value=None
        ), patch.object(client, "_collect_poc", return_value=[]):
            cve = client.fetch_cve("CVE-2026-1234")

        mitre_detail = next(
            detail for detail in cve["source_details"] if detail["source"] == "MITRE"
        )
        self.assertEqual(mitre_detail["status"], "unavailable")
        self.assertTrue(
            any(warning.startswith("MITRE could not be reached") for warning in cve["source_warnings"])
        )

    def test_sync_pages_nvd_results_without_requesting_poc_data(self):
        client = NVDClient(api_key="test-key")
        client.session.get = Mock(
            side_effect=[
                response(
                    {
                        "totalResults": 2,
                        "vulnerabilities": [{"cve": nvd_record("CVE-2026-1234")}],
                    }
                ),
                response(
                    {
                        "totalResults": 2,
                        "vulnerabilities": [{"cve": nvd_record("CVE-2026-5678")}],
                    }
                ),
            ]
        )
        db = Mock()

        with patch("nvd_client.time.sleep") as sleep, patch.object(
            client, "_collect_poc"
        ) as collect_poc:
            count = client.update_recent_cves(db, days_back=2)

        self.assertEqual(count, 2)
        self.assertEqual(db.store_cve.call_count, 2)
        self.assertEqual(db.store_cve.call_args_list[0].args[0]["poc"], [])
        starts = [
            call.kwargs["params"]["startIndex"]
            for call in client.session.get.call_args_list
        ]
        self.assertEqual(starts, [0, 1])
        self.assertTrue(
            all(
                call.kwargs["params"]["resultsPerPage"] == 2000
                for call in client.session.get.call_args_list
            )
        )
        self.assertTrue(
            all(
                "lastModStartDate" in call.kwargs["params"]
                for call in client.session.get.call_args_list
            )
        )
        self.assertEqual(db.log_update.call_args.args, (2,))
        self.assertEqual(db.log_update.call_args.kwargs, {"success": True})
        sleep.assert_called_once_with(0.7)
        collect_poc.assert_not_called()

    def test_cisa_kev_sync_mirrors_records_and_retains_changed_snapshots(self):
        client = NVDClient()
        catalog_entry = {
            "cveID": "CVE-2026-1234",
            "vendorProject": "Acme",
            "product": "Widget",
            "vulnerabilityName": "Widget command injection",
            "dateAdded": "2026-02-01",
            "dueDate": "2026-02-22",
            "knownRansomwareCampaignUse": "Unknown",
            "requiredAction": "Apply vendor updates.",
            "notes": "",
        }
        client.session.get = Mock(
            return_value=response({"vulnerabilities": [catalog_entry]})
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            db = CVEDatabase(Path(temp_dir) / "cves.db")
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "description": "Original NVD description.",
                    "source": "NVD",
                    "sources_checked": ["NVD"],
                }
            )
            first_count = client.sync_cisa_kev(db)
            client.session.get = Mock(
                return_value=response(
                    {
                        "vulnerabilities": [
                            {**catalog_entry, "notes": "Updated catalog note."}
                        ]
                    }
                )
            )
            second_count = client.sync_cisa_kev(db)
            client.session.get = Mock(
                return_value=response({"vulnerabilities": []})
            )
            third_count = client.sync_cisa_kev(db)
            cve = db.get_cve("CVE-2026-1234")
            stats = db.get_stats()
            del db

        self.assertEqual(first_count, 1)
        self.assertEqual(second_count, 1)
        self.assertEqual(third_count, 1)
        self.assertEqual(cve["description"], "Original NVD description.")
        self.assertEqual(cve["published"], "")
        self.assertIsNone(cve["cisa_kev"])
        self.assertEqual(len(cve["source_observations"]), 1)
        self.assertEqual(cve["source_observations"][0]["snapshot_count"], 3)
        self.assertEqual(
            next(
                detail
                for detail in cve["source_details"]
                if detail["source"] == "CISA KEV"
            )["status"],
            "no_matching_record",
        )
        self.assertEqual(stats["source_syncs"][0]["source"], "CISA KEV")
        self.assertTrue(stats["source_syncs"][0]["success"])
        self.assertEqual(stats["source_syncs"][0]["records_processed"], 1)

    def test_full_nvd_sync_paginates_and_records_source_history(self):
        client = NVDClient(api_key="test-key")
        client.session.get = Mock(
            side_effect=[
                response(
                    {
                        "totalResults": 2,
                        "vulnerabilities": [{"cve": nvd_record("CVE-2026-1234")}],
                    }
                ),
                response(
                    {
                        "totalResults": 2,
                        "vulnerabilities": [{"cve": nvd_record("CVE-2026-5678")}],
                    }
                ),
            ]
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            db = CVEDatabase(Path(temp_dir) / "cves.db")
            with patch("nvd_client.time.sleep") as sleep:
                count = client.sync_nvd_full(db)
            first = db.get_cve("CVE-2026-1234")
            stats = db.get_stats()
            del db

        self.assertEqual(count, 2)
        self.assertEqual(
            [call.kwargs["params"]["startIndex"] for call in client.session.get.call_args_list],
            [0, 1],
        )
        self.assertTrue(
            all(
                call.kwargs["params"]["resultsPerPage"] == 2000
                for call in client.session.get.call_args_list
            )
        )
        self.assertTrue(
            all(
                "lastModStartDate" not in call.kwargs["params"]
                for call in client.session.get.call_args_list
            )
        )
        self.assertEqual(first["source_observations"][0]["source"], "NVD")
        self.assertTrue(stats["source_syncs"][0]["success"])
        self.assertEqual(stats["source_syncs"][0]["records_processed"], 2)
        sleep.assert_called_once_with(0.7)

    def test_cisa_kev_sync_records_feed_failures(self):
        client = NVDClient()
        client.session.get = Mock(
            side_effect=requests.ConnectionError("offline")
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            db = CVEDatabase(Path(temp_dir) / "cves.db")
            with self.assertRaises(CISAKEVUpdateError):
                client.sync_cisa_kev(db)
            sync = db.get_stats()["source_syncs"][0]
            del db

        self.assertEqual(sync["source"], "CISA KEV")
        self.assertFalse(sync["success"])
        self.assertIn("offline", sync["error"])

    def test_logs_failed_sync_when_nvd_request_fails(self):
        client = NVDClient()
        failed_response = Mock()
        failed_response.raise_for_status.side_effect = requests.HTTPError("rate limited")
        client.session.get = Mock(return_value=failed_response)
        db = Mock()

        with self.assertRaises(NVDUpdateError):
            client.update_recent_cves(db)

        db.log_update.assert_called_once_with(0, success=False)

    def test_rejects_sync_windows_over_nvd_limit(self):
        client = NVDClient()
        client.session.get = Mock()
        db = Mock()

        with self.assertRaises(ValueError):
            client.update_recent_cves(db, days_back=121)

        client.session.get.assert_not_called()
        db.log_update.assert_not_called()

    def test_extracts_cvss_v4(self):
        record = nvd_record("CVE-2026-1234")
        record["lastModified"] = "2026-02-03T04:05:06.000"
        record["vulnStatus"] = "Analyzed"
        record["metrics"] = {
            "cvssMetricV40": [
                {
                    "cvssData": {
                        "version": "4.0",
                        "baseScore": 9.3,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:4.0/AV:N/AC:L",
                        "attackVector": "NETWORK",
                    },
                    "baseSeverity": "CRITICAL",
                }
            ]
        }

        parsed = NVDClient()._parse_nvd(record)

        self.assertEqual(parsed["cvss_v4"]["score"], 9.3)
        self.assertEqual(parsed["cvss_v4"]["vector"], "CVSS:4.0/AV:N/AC:L")
        observation = parsed["source_records"][0]
        self.assertEqual(observation["source"], "NVD")
        self.assertEqual(observation["record_id"], "CVE-2026-1234")
        self.assertEqual(observation["source_updated_at"], record["lastModified"])
        self.assertEqual(observation["review_status"], "Analyzed")
        self.assertEqual(observation["claims"]["cvss"]["cvss_v4"]["score"], 9.3)
        self.assertEqual(observation["payload"], record)

    def test_mitre_parser_includes_cna_versions_and_cisa_adp_assessments(self):
        record = {
            "cveMetadata": {
                "cveId": "CVE-2022-22965",
                "datePublished": "2022-04-01T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "descriptions": [
                        {"lang": "en", "value": "Spring Framework vulnerability"}
                    ],
                    "affected": [
                        {
                            "vendor": "VMware",
                            "product": "Spring Framework",
                            "versions": [
                                {
                                    "version": "5.3.0",
                                    "lessThan": "5.3.18",
                                    "status": "affected",
                                }
                            ],
                        }
                    ],
                },
                "adp": [
                    {
                        "providerMetadata": {"shortName": "CISA-ADP"},
                        "metrics": [
                            {
                                "cvssV3_1": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": "CVSS:3.1/AV:N",
                                }
                            },
                            {
                                "other": {
                                    "type": "kev",
                                    "content": {
                                        "dateAdded": "2022-04-04",
                                        "reference": "https://www.cisa.gov/kev",
                                    },
                                }
                            },
                            {
                                "other": {
                                    "type": "ssvc",
                                    "content": {"options": [{"Exploitation": "active"}]},
                                }
                            },
                        ],
                    }
                ],
            },
        }

        parsed = NVDClient()._parse_mitre(record)

        self.assertEqual(parsed["cvss_v3"]["score"], 9.8)
        self.assertEqual(parsed["affected_systems"][0]["version_range"], ">= 5.3.0, < 5.3.18")
        self.assertEqual(parsed["cisa_kev"]["date_added"], "2022-04-04")
        self.assertEqual(parsed["ssvc"][0]["options"][0]["Exploitation"], "active")

    def test_incomplete_cached_records_are_rechecked_daily(self):
        old = datetime.now(timezone.utc) - timedelta(days=2)
        cached = {
            "cvss_v3": None,
            "cvss_v2": None,
            "cvss_v4": None,
            "affected_systems": [{"product": "Spring Framework"}],
            "fetched_at": old.isoformat(),
            "sources_checked": [
                "NVD",
                "MITRE",
                "OSV",
                "GitHub Advisory",
                "Red Hat Security Data",
                "CISA KEV",
            ],
            "source_warnings": [],
        }
        recent = {**cached, "fetched_at": datetime.now(timezone.utc).isoformat()}

        self.assertTrue(NVDClient.cache_needs_refresh(cached))
        self.assertFalse(NVDClient.cache_needs_refresh(recent))

    def test_records_without_osv_enrichment_are_refreshed(self):
        cached = {
            "cvss_v3": {"score": 9.8},
            "affected_systems": [{"product": "Spring Framework"}],
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "sources_checked": ["NVD", "MITRE"],
            "source_warnings": [],
        }

        self.assertTrue(NVDClient.cache_needs_refresh(cached))

    def test_records_without_redhat_enrichment_are_refreshed(self):
        cached = {
            "cvss_v3": {"score": 9.8},
            "affected_systems": [{"product": "Spring Framework", "status": "affected"}],
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "sources_checked": [
                "NVD",
                "MITRE",
                "OSV",
                "GitHub Advisory",
                "CISA KEV",
            ],
            "source_warnings": [],
        }

        self.assertTrue(NVDClient.cache_needs_refresh(cached))

    def test_upstream_warnings_are_retried_after_a_day(self):
        fetched_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        cached = {
            "cvss_v3": {"score": 9.8},
            "affected_systems": [{"product": "Spring Framework", "status": "affected"}],
            "fetched_at": fetched_at.isoformat(),
            "sources_checked": [
                "NVD",
                "MITRE",
                "OSV",
                "GitHub Advisory",
                "Red Hat Security Data",
                "CISA KEV",
            ],
            "source_warnings": ["OSV could not be reached."],
        }

        self.assertFalse(
            NVDClient.cache_needs_refresh(
                cached, now=fetched_at + timedelta(hours=12)
            )
        )
        self.assertTrue(
            NVDClient.cache_needs_refresh(
                cached, now=fetched_at + timedelta(hours=24)
            )
        )

    def test_cached_version_ranges_from_older_parser_are_refreshed(self):
        cached = {
            "cvss_v3": {"score": 9.8},
            "affected_systems": [{"version_start": "1.0", "version_end": "2.0"}],
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }

        self.assertTrue(NVDClient.cache_needs_refresh(cached))

    def test_extracts_osv_ecosystem_version_ranges(self):
        affected = NVDClient._extract_osv_affected(
            [
                {
                    "package": {"name": "Kernel", "ecosystem": "Linux"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "7.2.0"},
                                {"fixed": "7.2.13"},
                            ],
                        }
                    ],
                }
            ]
        )

        self.assertEqual(len(affected), 1)
        self.assertEqual(affected[0]["vendor"], "Linux")
        self.assertEqual(affected[0]["product"], "Kernel")
        self.assertEqual(affected[0]["version_range"], ">= 7.2.0, < 7.2.13")
        self.assertEqual(affected[0]["source"], "OSV")

    def test_osv_merge_adds_packages_without_dropping_mitre_assessments(self):
        nvd_record_data = {
            "id": "CVE-2026-1234",
            "source": "NVD",
            "cvss_v3": {"score": 8.0},
            "affected_systems": [],
            "refs": [],
            "cwes": [],
        }
        mitre_record_data = {
            "id": "CVE-2026-1234",
            "source": "MITRE",
            "cvss_v3": None,
            "affected_systems": [],
            "refs": [],
            "cwes": [],
            "cisa_kev": {"date_added": "2026-01-01"},
            "ssvc": [{"options": [{"Exploitation": "active"}]}],
        }
        osv_record_data = {
            "id": "CVE-2026-1234",
            "source": "OSV",
            "cvss_v3": None,
            "affected_systems": [
                {
                    "vendor": "Linux",
                    "product": "Kernel",
                    "version_range": ">= 7.2.0, < 7.2.13",
                    "status": "affected",
                    "source": "OSV",
                }
            ],
            "refs": [],
            "cwes": [],
        }

        merged = NVDClient._merge_records(
            NVDClient._merge_records(nvd_record_data, mitre_record_data),
            osv_record_data,
        )

        self.assertEqual(merged["source"], "NVD + MITRE + OSV")
        self.assertEqual(merged["cvss_v3"]["score"], 8.0)
        self.assertEqual(merged["cisa_kev"]["date_added"], "2026-01-01")
        self.assertEqual(merged["ssvc"][0]["options"][0]["Exploitation"], "active")
        self.assertEqual(merged["affected_systems"][0]["source"], "OSV")

    def test_verified_score_replaces_an_unverified_score(self):
        unverified = {
            "id": "CVE-2026-1234",
            "source": "Red Hat Security Data",
            "cvss_v3": {
                "score": 8.1,
                "untrusted": True,
                "trust_level": "unverified",
            },
            "affected_systems": [],
            "refs": [],
            "cwes": [],
        }
        reviewed = {
            "id": "CVE-2026-1234",
            "source": "GitHub Advisory",
            "cvss_v3": {
                "score": 7.5,
                "untrusted": False,
                "trust_level": "curated",
            },
            "affected_systems": [],
            "refs": [],
            "cwes": [],
        }

        merged = NVDClient._merge_records(unverified, reviewed)

        self.assertEqual(merged["cvss_v3"]["score"], 7.5)
        self.assertEqual(merged["cvss_v3"]["trust_level"], "curated")

    def test_keyword_search_returns_the_latest_nvd_page(self):
        client = NVDClient()
        client.session.get = Mock(
            side_effect=[
                response(
                    {
                        "totalResults": 10,
                        "vulnerabilities": [
                            {"cve": nvd_record("CVE-2009-1234")}
                        ],
                    }
                ),
                response(
                    {
                        "totalResults": 10,
                        "vulnerabilities": [
                            {"cve": nvd_record("CVE-2026-1234")}
                        ],
                    }
                ),
            ]
        )

        results, total = client.search_cves("Spring Framework", limit=1)

        self.assertEqual(total, 10)
        self.assertEqual(results[0]["id"], "CVE-2026-1234")
        self.assertEqual(
            client.session.get.call_args_list[1].kwargs["params"]["startIndex"],
            9,
        )

    def test_all_upstream_failures_are_not_reported_as_not_found(self):
        client = NVDClient()
        client.session.get = Mock(side_effect=requests.ConnectionError("offline"))

        with self.assertRaises(CVEUpstreamError):
            client.fetch_cve("CVE-2026-1234")

    def test_redhat_vendor_data_adds_verified_scores_and_package_states(self):
        client = NVDClient()
        client.session.get = Mock(
            return_value=response(
                {
                    "name": "CVE-2026-1234",
                    "public_date": "2026-01-01T00:00:00Z",
                    "details": ["Red Hat vendor-specific details."],
                    "threat_severity": "Important",
                    "cvss3": {
                        "cvss3_base_score": "8.1",
                        "cvss3_scoring_vector": "CVSS:3.1/AV:N/AC:H",
                        "status": "verified",
                    },
                    "package_state": [
                        {
                            "product_name": "Red Hat Enterprise Linux 9",
                            "package_name": "example-package",
                            "fix_state": "Affected",
                            "cpe": "cpe:/o:redhat:enterprise_linux:9",
                        },
                        {
                            "product_name": "Red Hat Enterprise Linux 8",
                            "package_name": "example-package",
                            "fix_state": "Not affected",
                        },
                    ],
                    "affected_release": [
                        {
                            "product_name": "Red Hat Enterprise Linux 9.1",
                            "package": "example-package-1.2.3",
                            "advisory": "RHSA-2026:1234",
                            "release_date": "2026-01-02T00:00:00Z",
                        }
                    ],
                    "references": ["https://example.com/advisory"],
                    "cwe": "CWE-79",
                }
            )
        )

        record = client._fetch_redhat_cve("CVE-2026-1234")

        self.assertEqual(record["cvss_v3"]["score"], 8.1)
        self.assertEqual(record["cvss_v3"]["severity"], "HIGH")
        self.assertFalse(record["cvss_v3"]["untrusted"])
        self.assertEqual(
            [system["status"] for system in record["affected_systems"]],
            ["affected", "unaffected", "fixed"],
        )
        self.assertEqual(record["affected_systems"][0]["version"], "example-package (Affected)")
        self.assertEqual(record["affected_systems"][0]["cpe"], "cpe:/o:redhat:enterprise_linux:9")
        self.assertIn(
            "https://access.redhat.com/errata/RHSA-2026:1234",
            {ref["url"] for ref in record["refs"]},
        )
        self.assertIn(
            f"{REDHAT_CVE_API}/CVE-2026-1234.json",
            {ref["url"] for ref in record["refs"]},
        )
        self.assertEqual(record["source_details"][0]["trust_level"], "authoritative")
        self.assertEqual(client.session.get.call_args.args[0], f"{REDHAT_CVE_API}/CVE-2026-1234.json")

    def test_redhat_draft_cvss_is_flagged_unverified(self):
        client = NVDClient()
        client.session.get = Mock(
            return_value=response(
                {
                    "name": "CVE-2026-1234",
                    "cvss3": {
                        "cvss3_base_score": "8.1",
                        "cvss3_scoring_vector": "CVSS:3.1/AV:N/AC:H",
                        "status": "draft",
                    },
                }
            )
        )

        record = client._fetch_redhat_cve("CVE-2026-1234")

        self.assertEqual(record["cvss_v3"]["trust_level"], "unverified")
        self.assertTrue(record["cvss_v3"]["untrusted"])

    def test_cisa_kev_feed_is_cached_and_marks_exploitation(self):
        client = NVDClient()
        client.session.get = Mock(
            return_value=response(
                {
                    "catalogVersion": "2026.10.30",
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2026-1234",
                            "dateAdded": "2026-10-30",
                            "dueDate": "2026-11-20",
                            "knownRansomwareCampaignUse": "Known",
                            "requiredAction": "Apply the vendor update.",
                            "notes": "Test record.",
                        }
                    ],
                }
            )
        )

        record = client._fetch_cisa_kev("CVE-2026-1234")
        missing_record = client._fetch_cisa_kev("CVE-2026-5678")

        self.assertEqual(record["cisa_kev"]["date_added"], "2026-10-30")
        self.assertEqual(record["cisa_kev"]["due_date"], "2026-11-20")
        self.assertEqual(
            record["cisa_kev"]["known_ransomware_campaign_use"],
            "Known",
        )
        self.assertEqual(record["source"], "CISA KEV")
        self.assertFalse(record["source_details"][0]["untrusted"])
        self.assertIsNone(missing_record)
        client.session.get.assert_called_once_with(CISA_KEV_FEED, timeout=20)

    def test_cisa_kev_catalog_overrides_older_adp_details(self):
        existing = {
            "id": "CVE-2026-1234",
            "source": "MITRE",
            "cisa_kev": {"date_added": "2026-10-01"},
            "affected_systems": [],
            "refs": [],
            "cwes": [],
        }
        catalog = {
            "id": "CVE-2026-1234",
            "source": "CISA KEV",
            "cisa_kev": {"date_added": "2026-10-30"},
            "affected_systems": [],
            "refs": [],
            "cwes": [],
        }

        merged = NVDClient._merge_records(existing, catalog)

        self.assertEqual(merged["cisa_kev"]["date_added"], "2026-10-30")

    def test_poc_references_are_marked_unverified(self):
        client = NVDClient()
        exploitdb_response = response(
            {
                "data": [
                    {
                        "id": "12345",
                        "description": "Community exploit",
                        "type": {"name": "remote"},
                        "platform": {"name": "multiple"},
                        "author": {"name": "Researcher"},
                    }
                ]
            }
        )
        exploitdb_response.status_code = 200
        github_response = response(
            [
                {
                    "name": "PoC repository",
                    "html_url": "https://github.com/example/poc",
                    "description": "Community PoC",
                    "stargazers_count": 1,
                }
            ]
        )
        github_response.status_code = 200
        client.session.get = Mock(side_effect=[exploitdb_response, github_response])

        pocs = client._collect_poc("CVE-2026-1234")

        self.assertEqual(len(pocs), 2)
        self.assertTrue(all(poc["untrusted"] for poc in pocs))
        self.assertTrue(all(poc["trust_level"] == "unverified" for poc in pocs))

    def test_unreviewed_github_advisory_is_marked_untrusted(self):
        client = NVDClient()
        client.session.get = Mock(
            return_value=response(
                [
                    {
                        "ghsa_id": "GHSA-1234-5678-90ab",
                        "html_url": "https://github.com/advisories/GHSA-1234-5678-90ab",
                        "cve_id": "CVE-2026-1234",
                        "type": "unreviewed",
                        "severity": "high",
                        "cvss": {
                            "vector_string": "CVSS:3.1/AV:N/AC:L",
                            "score": 8.2,
                        },
                        "vulnerabilities": [
                            {
                                "package": {
                                    "name": "example-package",
                                    "ecosystem": "npm",
                                },
                                "vulnerable_version_range": "< 2.0.0",
                                "first_patched_version": "2.0.0",
                            }
                        ],
                    }
                ]
            )
        )

        record = client._fetch_github_advisory("CVE-2026-1234")

        self.assertEqual(record["cvss_v3"]["score"], 8.2)
        self.assertTrue(record["cvss_v3"]["untrusted"])
        self.assertEqual(record["cvss_v3"]["trust_level"], "unverified")
        self.assertTrue(record["affected_systems"][0]["untrusted"])
        self.assertEqual(record["affected_systems"][0]["version_range"], "< 2.0.0")
        self.assertEqual(record["affected_systems"][0]["patched_version"], "2.0.0")
        self.assertTrue(record["refs"][0]["untrusted"])
        self.assertEqual(record["source_details"][0]["record_type"], "unreviewed")

    def test_github_advisory_ignores_malformed_patched_version(self):
        client = NVDClient()
        client.session.get = Mock(
            return_value=response(
                [
                    {
                        "cve_id": "CVE-2026-1234",
                        "type": "unreviewed",
                        "vulnerabilities": [
                            {
                                "package": {
                                    "name": "example-package",
                                    "ecosystem": "npm",
                                },
                                "first_patched_version": [],
                            }
                        ],
                    }
                ]
            )
        )

        record = client._fetch_github_advisory("CVE-2026-1234")

        self.assertIsNone(record["affected_systems"][0]["patched_version"])

    def test_github_advisory_merges_all_matches_and_prefers_reviewed_scores(self):
        client = NVDClient()
        client.session.get = Mock(
            return_value=response(
                [
                    {
                        "ghsa_id": "GHSA-unreviewed",
                        "cve_id": "CVE-2026-1234",
                        "type": "unreviewed",
                        "severity": "high",
                        "cvss": {"vector_string": "CVSS:3.1/AV:N", "score": 8.2},
                        "vulnerabilities": [
                            {
                                "package": {
                                    "name": "unreviewed-package",
                                    "ecosystem": "npm",
                                },
                                "vulnerable_version_range": "< 2.0.0",
                            }
                        ],
                    },
                    {
                        "ghsa_id": "GHSA-reviewed",
                        "cve_id": "CVE-2026-1234",
                        "type": "reviewed",
                        "severity": "high",
                        "cvss": {"vector_string": "CVSS:3.1/AV:N", "score": 7.5},
                        "vulnerabilities": [
                            {
                                "package": {
                                    "name": "reviewed-package",
                                    "ecosystem": "npm",
                                },
                                "vulnerable_version_range": "< 3.0.0",
                            }
                        ],
                    },
                ]
            )
        )

        record = client._fetch_github_advisory("CVE-2026-1234")

        self.assertEqual(len(record["affected_systems"]), 2)
        self.assertEqual(record["cvss_v3"]["score"], 7.5)
        self.assertFalse(record["cvss_v3"]["untrusted"])
        self.assertEqual(len(record["source_details"]), 2)

    def test_reviewed_github_advisory_is_not_flagged_untrusted(self):
        client = NVDClient()
        client.session.get = Mock(
            return_value=response(
                [
                    {
                        "ghsa_id": "GHSA-1234-5678-90ab",
                        "cve_id": "CVE-2026-1234",
                        "type": "reviewed",
                        "severity": "high",
                        "cvss": {"vector_string": None, "score": None},
                        "vulnerabilities": [],
                    }
                ]
            )
        )

        record = client._fetch_github_advisory("CVE-2026-1234")

        self.assertFalse(record["source_details"][0]["untrusted"])
        self.assertEqual(record["source_details"][0]["trust_level"], "curated")


if __name__ == "__main__":
    unittest.main()
