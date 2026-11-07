import unittest
from unittest.mock import Mock

import requests

from epss_client import EPSSError, EPSSClient


def response(payload):
    item = Mock()
    item.json.return_value = payload
    item.raise_for_status.return_value = None
    return item


class EPSSClientTests(unittest.TestCase):
    def test_returns_normalized_score_and_provenance(self):
        session = Mock()
        session.get.return_value = response({
            "status": "OK",
            "data": [{
                "cve": "CVE-2021-44228",
                "epss": "0.975",
                "percentile": "0.999",
                "date": "2026-11-06",
            }],
        })
        result = EPSSClient(session=session).fetch("CVE-2021-44228")

        self.assertEqual(result["source"], "FIRST EPSS")
        self.assertEqual(result["claims"]["epss"], 0.975)
        self.assertEqual(result["claims"]["percentile"], 0.999)
        self.assertEqual(result["source_updated_at"], "2026-11-06")
        self.assertEqual(result["trust_level"], "authoritative")
        session.get.assert_called_once_with(
            "https://api.first.org/data/v1/epss",
            params={"cve": "CVE-2021-44228"},
            timeout=10,
        )

    def test_no_matching_cve_is_confirmed_absence(self):
        session = Mock()
        session.get.return_value = response({"data": []})
        self.assertIsNone(EPSSClient(session=session).fetch("CVE-2021-44228"))

    def test_rejects_invalid_score_ranges(self):
        session = Mock()
        session.get.return_value = response({
            "data": [{
                "cve": "CVE-2021-44228",
                "epss": "1.2",
                "percentile": "0.5",
            }],
        })
        with self.assertRaises(EPSSError):
            EPSSClient(session=session).fetch("CVE-2021-44228")

    def test_propagates_upstream_errors(self):
        session = Mock()
        session.get.side_effect = requests.Timeout("timeout")
        with self.assertRaises(requests.Timeout):
            EPSSClient(session=session).fetch("CVE-2021-44228")


if __name__ == "__main__":
    unittest.main()
