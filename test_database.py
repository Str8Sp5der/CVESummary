import tempfile
import unittest
from pathlib import Path

from database import CVEDatabase


class CVEDatabaseTests(unittest.TestCase):
    def test_full_text_index_tracks_inserts_and_updates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = CVEDatabase(Path(temp_dir) / "cves.db")
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "description": "Spring Framework test issue",
                }
            )
            initial = db.search_cves("Spring")
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "description": "Updated Framework test issue",
                }
            )
            removed_term = db.search_cves("Spring")
            added_term = db.search_cves("Updated")
            del db

        self.assertEqual([item["id"] for item in initial], ["CVE-2026-1234"])
        self.assertEqual(removed_term, [])
        self.assertEqual([item["id"] for item in added_term], ["CVE-2026-1234"])

    def test_updating_nvd_metadata_preserves_existing_poc_results(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = CVEDatabase(Path(temp_dir) / "cves.db")
            poc = [{"title": "Existing PoC", "source": "GitHub"}]
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "description": "Original description",
                    "poc": poc,
                    "source": "MITRE",
                }
            )
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "description": "Updated description",
                    "poc": [],
                    "source": "NVD",
                }
            )

            cve = db.get_cve("CVE-2026-1234")
            del db

        self.assertEqual(cve["description"], "Updated description")
        self.assertEqual(cve["source"], "NVD")
        self.assertEqual(cve["poc"], poc)

    def test_persists_cvss_v4_and_cisa_kev_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = CVEDatabase(Path(temp_dir) / "cves.db")
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "cvss_v4": {
                        "score": 9.3,
                        "severity": "CRITICAL",
                        "vector": "CVSS:4.0/AV:N",
                    },
                    "cisa_kev": {"date_added": "2026-01-02"},
                    "ssvc": [{"options": [{"Exploitation": "active"}]}],
                }
            )
            cve = db.get_cve("CVE-2026-1234")
            del db

        self.assertEqual(cve["cvss_v4"]["score"], 9.3)
        self.assertEqual(cve["severity"], "CRITICAL")
        self.assertEqual(cve["cvss_score"], 9.3)
        self.assertEqual(cve["cisa_kev"]["date_added"], "2026-01-02")
        self.assertEqual(cve["ssvc"][0]["options"][0]["Exploitation"], "active")

    def test_persists_source_checks_and_warnings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = CVEDatabase(Path(temp_dir) / "cves.db")
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "sources_checked": ["NVD", "MITRE", "OSV"],
                    "source_details": [
                        {
                            "source": "GitHub Advisory (unreviewed)",
                            "trust_level": "unverified",
                            "untrusted": True,
                        }
                    ],
                    "source_warnings": ["OSV could not be reached."],
                }
            )
            cve = db.get_cve("CVE-2026-1234")
            del db

        self.assertEqual(cve["sources_checked"], ["NVD", "MITRE", "OSV"])
        github_detail = next(
            detail
            for detail in cve["source_details"]
            if detail["source"] == "GitHub Advisory (unreviewed)"
        )
        self.assertTrue(github_detail["untrusted"])
        self.assertEqual(
            next(
                detail["status"]
                for detail in cve["source_details"]
                if detail["source"] == "OSV"
            ),
            "unavailable",
        )
        self.assertEqual(cve["source_warnings"], ["OSV could not be reached."])

    def test_source_observations_keep_changed_snapshots_and_deduplicate_repeats(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = CVEDatabase(Path(temp_dir) / "cves.db")
            observation = {
                "source": "NVD",
                "record_id": "CVE-2026-1234",
                "source_updated_at": "2026-01-02T00:00:00.000",
                "retrieved_at": "2026-01-03T00:00:00+00:00",
                "trust_level": "authoritative",
                "review_status": "Analyzed",
                "claims": {
                    "description": "Provider description.",
                    "cvss": {
                        "cvss_v3": {
                            "score": 8.1,
                            "severity": "HIGH",
                            "source": "NVD",
                        }
                    },
                    "affected_count": 2,
                },
                "payload": {"id": "CVE-2026-1234", "vulnStatus": "Analyzed"},
            }
            data = {
                "id": "CVE-2026-1234",
                "source_records": [observation],
            }
            db.store_cve(data)
            observation["retrieved_at"] = "2026-01-03T00:00:00+00:00"
            db.store_cve(data)
            repeated = db.get_cve("CVE-2026-1234")["source_observations"][0]
            self.assertEqual(
                repeated["retrieved_at"],
                "2026-01-03T00:00:00+00:00",
            )
            observation["payload"] = {
                "id": "CVE-2026-1234",
                "vulnStatus": "Modified",
            }
            observation["source_updated_at"] = "2026-01-04T00:00:00.000"
            observation["retrieved_at"] = "2026-01-04T00:00:00+00:00"
            db.store_cve(data)

            cve = db.get_cve("CVE-2026-1234")
            stats = db.get_stats()
            del db

        self.assertEqual(len(cve["source_observations"]), 1)
        latest = cve["source_observations"][0]
        self.assertEqual(latest["source"], "NVD")
        self.assertEqual(latest["source_updated_at"], "2026-01-04T00:00:00.000")
        self.assertEqual(latest["review_status"], "Analyzed")
        self.assertEqual(latest["snapshot_count"], 2)
        self.assertEqual(latest["claims"]["cvss"]["cvss_v3"]["score"], 8.1)
        self.assertNotIn("payload_json", latest)
        self.assertEqual(stats["source_observation_snapshots"], 2)
        self.assertEqual(stats["source_observation_sources"], 1)

    def test_rejecting_invalid_source_observations_rolls_back_cve_write(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = CVEDatabase(Path(temp_dir) / "cves.db")
            with self.assertRaises(ValueError):
                db.store_cve(
                    {
                        "id": "CVE-2026-1234",
                        "source_records": [
                            {
                                "source": "NVD",
                                "record_id": "CVE-2026-1234",
                                "payload": "not a source record",
                            }
                        ],
                    }
                )
            cve = db.get_cve("CVE-2026-1234")
            del db

        self.assertIsNone(cve)

    def test_nvd_updates_preserve_other_sources_affected_ranges_and_references(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = CVEDatabase(Path(temp_dir) / "cves.db")
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "source": "NVD + MITRE + OSV",
                    "affected_systems": [
                        {
                            "vendor": "Acme",
                            "product": "Widget",
                            "version": "1.0",
                            "version_range": "1.0",
                            "status": "affected",
                            "source": "NVD + MITRE",
                            "sources": ["NVD", "MITRE"],
                            "untrusted": False,
                        },
                        {
                            "vendor": "Linux",
                            "product": "Kernel",
                            "version": "7.2.0",
                            "version_range": ">= 7.2.0, < 7.2.13",
                            "status": "affected",
                            "source": "OSV",
                            "untrusted": False,
                        },
                    ],
                    "refs": [
                        {"url": "https://nvd.example/cve", "source": "NVD"},
                        {"url": "https://osv.example/cve", "source": "OSV"},
                    ],
                }
            )
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "source": "NVD",
                    "provider_updates": ["NVD"],
                    "source_details": [{"source": "NVD", "status": "successful"}],
                    "untrusted": False,
                    "affected_systems": [
                        {
                            "vendor": "Acme",
                            "product": "Widget",
                            "version": "1.1",
                            "version_range": "1.1",
                            "status": "affected",
                            "source": "NVD",
                        }
                    ],
                    "refs": [{"url": "https://nvd.example/updated", "source": "NVD"}],
                }
            )
            cve = db.get_cve("CVE-2026-1234")
            del db

        systems = cve["affected_systems"]
        self.assertIn(
            ("Widget", "1.0", "MITRE"),
            [(item["product"], item["version"], item["source"]) for item in systems],
        )
        self.assertIn(
            ("Widget", "1.1", "NVD"),
            [(item["product"], item["version"], item["source"]) for item in systems],
        )
        self.assertIn(
            ("Kernel", "OSV"),
            [(item["product"], item["source"]) for item in systems],
        )
        self.assertEqual(
            {ref["url"] for ref in cve["refs"]},
            {
                "https://osv.example/cve",
                "https://nvd.example/updated",
            },
        )

    def test_untrusted_provenance_survives_merge_with_trusted_source(self):
        systems = CVEDatabase._merge_affected_systems(
            [],
            [
                {
                    "vendor": "npm",
                    "product": "example-package",
                    "version_range": "< 2.0.0",
                    "status": "affected",
                    "source": "GitHub Advisory (unreviewed)",
                    "trust_level": "unverified",
                    "untrusted": True,
                },
                {
                    "vendor": "npm",
                    "product": "example-package",
                    "version_range": "< 2.0.0",
                    "status": "affected",
                    "source": "MITRE",
                    "trust_level": "authoritative",
                    "untrusted": False,
                },
            ],
            "NVD + MITRE + OSV + GitHub Advisory",
        )

        self.assertEqual(len(systems), 1)
        self.assertEqual(
            systems[0]["source"],
            "GitHub Advisory (unreviewed) + MITRE",
        )
        self.assertTrue(systems[0]["untrusted"])
        self.assertEqual(systems[0]["trust_level"], "unverified")

    def test_refresh_replaces_only_references_from_checked_sources(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = CVEDatabase(Path(temp_dir) / "cves.db")
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "sources_checked": ["NVD", "OSV"],
                    "refs": [
                        {
                            "url": "https://nvd.example/old",
                            "source": "Vendor",
                            "sources": ["NVD"],
                        },
                        {
                            "url": "https://osv.example/advisory",
                            "source": "OSV",
                            "sources": ["OSV"],
                        },
                        {
                            "url": "https://nvd.example/shared",
                            "source": "Vendor",
                            "sources": ["NVD", "OSV"],
                        },
                    ],
                }
            )
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "source": "NVD",
                    "sources_checked": ["NVD"],
                    "provider_updates": ["NVD"],
                    "source_details": [{"source": "NVD", "status": "successful"}],
                    "refs": [
                        {
                            "url": "https://nvd.example/new",
                            "source": "Vendor",
                            "sources": ["NVD"],
                        },
                        {
                            "url": "https://nvd.example/shared",
                            "source": "Vendor",
                            "sources": ["NVD"],
                        },
                    ],
                }
            )
            cve = db.get_cve("CVE-2026-1234")
            del db

        refs = {ref["url"]: ref for ref in cve["refs"]}
        self.assertNotIn("https://nvd.example/old", refs)
        self.assertIn("https://nvd.example/new", refs)
        self.assertIn("https://osv.example/advisory", refs)
        self.assertEqual(
            refs["https://nvd.example/shared"]["sources"],
            ["NVD", "OSV"],
        )

    def test_refresh_removes_affected_entries_from_a_checked_source(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = CVEDatabase(Path(temp_dir) / "cves.db")
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "source": "MITRE + GitHub Advisory (unreviewed)",
                    "sources_checked": ["MITRE", "GitHub Advisory"],
                    "affected_systems": [
                        {
                            "vendor": "npm",
                            "product": "old-package",
                            "version_range": "< 2.0.0",
                            "status": "affected",
                            "source": "GitHub Advisory (unreviewed)",
                        },
                        {
                            "vendor": "Acme",
                            "product": "Other Widget",
                            "version_range": "< 4.0.0",
                            "status": "affected",
                            "source": "MITRE",
                        },
                    ],
                }
            )
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "source": "MITRE",
                    "sources_checked": ["MITRE", "GitHub Advisory"],
                    "provider_updates": ["MITRE", "GitHub Advisory"],
                    "source_details": [
                        {"source": "MITRE", "status": "successful"},
                        {"source": "GitHub Advisory", "status": "successful"},
                    ],
                    "affected_systems": [
                        {
                            "vendor": "Acme",
                            "product": "Other Widget",
                            "version_range": "< 4.0.0",
                            "status": "affected",
                            "source": "MITRE",
                        }
                    ],
                }
            )
            cve = db.get_cve("CVE-2026-1234")
            del db

        self.assertEqual(
            [system["product"] for system in cve["affected_systems"]],
            ["Other Widget"],
        )

    def test_refresh_can_remove_all_data_from_a_checked_source(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = CVEDatabase(Path(temp_dir) / "cves.db")
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "source": "GitHub Advisory",
                    "sources_checked": ["GitHub Advisory"],
                    "affected_systems": [
                        {
                            "vendor": "npm",
                            "product": "example-package",
                            "version_range": "< 2.0.0",
                            "status": "affected",
                            "source": "GitHub Advisory",
                        }
                    ],
                    "refs": [
                        {
                            "url": "https://github.com/advisories/GHSA-old",
                            "sources": ["GitHub Advisory"],
                        }
                    ],
                }
            )
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "source": "GitHub Advisory",
                    "sources_checked": ["GitHub Advisory"],
                    "provider_updates": ["GitHub Advisory"],
                    "source_details": [
                        {"source": "GitHub Advisory", "status": "successful"}
                    ],
                    "affected_systems": [],
                    "refs": [],
                }
            )
            cve = db.get_cve("CVE-2026-1234")
            del db

        self.assertEqual(cve["affected_systems"], [])
        self.assertEqual(cve["refs"], [])

    def test_unavailable_source_does_not_delete_its_cached_data(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = CVEDatabase(Path(temp_dir) / "cves.db")
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "source": "GitHub Advisory",
                    "sources_checked": ["GitHub Advisory"],
                    "affected_systems": [
                        {
                            "vendor": "npm",
                            "product": "example-package",
                            "version_range": "< 2.0.0",
                            "status": "affected",
                            "source": "GitHub Advisory (unreviewed)",
                        }
                    ],
                    "refs": [
                        {
                            "url": "https://github.com/advisories/GHSA-test",
                            "sources": ["GitHub Advisory"],
                        }
                    ],
                }
            )
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "source": "GitHub Advisory",
                    "sources_checked": ["GitHub Advisory"],
                    "source_details": [
                        {
                            "source": "GitHub Advisory",
                            "status": "unavailable",
                            "trust_level": "unknown",
                            "untrusted": False,
                        }
                    ],
                    "affected_systems": [],
                    "refs": [],
                }
            )
            cve = db.get_cve("CVE-2026-1234")
            del db

        self.assertEqual(
            cve["affected_systems"][0]["product"],
            "example-package",
        )
        self.assertEqual(
            cve["refs"][0]["url"],
            "https://github.com/advisories/GHSA-test",
        )

    def test_nvd_refresh_replaces_legacy_untagged_ranges(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = CVEDatabase(Path(temp_dir) / "cves.db")
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "source": "NVD",
                    "provider_updates": ["NVD"],
                    "source_details": [{"source": "NVD", "status": "successful"}],
                    "affected_systems": [
                        {
                            "vendor": "Acme",
                            "product": "Widget",
                            "version": "1.0",
                        }
                    ],
                }
            )
            db.store_cve(
                {
                    "id": "CVE-2026-1234",
                    "source": "NVD",
                    "provider_updates": ["NVD"],
                    "source_details": [{"source": "NVD", "status": "successful"}],
                    "affected_systems": [
                        {
                            "vendor": "Acme",
                            "product": "Widget",
                            "version": "2.0",
                            "source": "NVD",
                        }
                    ],
                }
            )
            cve = db.get_cve("CVE-2026-1234")
            del db

        self.assertEqual([item["version"] for item in cve["affected_systems"]], ["2.0"])


if __name__ == "__main__":
    unittest.main()
