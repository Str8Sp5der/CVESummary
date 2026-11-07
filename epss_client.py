"""FIRST EPSS enrichment adapter.

The EPSS API is used for single-CVE lookups only. Bulk synchronization belongs
in a separate feed importer because FIRST explicitly recommends its daily CSV
for bulk use.
"""
from datetime import datetime, timezone

import requests

EPSS_API = "https://api.first.org/data/v1/epss"


class EPSSError(ValueError):
    """The EPSS provider returned an invalid response."""


class EPSSClient:
    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.session.headers.update({
            "User-Agent": "CVESummary/1.0",
            "Accept": "application/json",
        })

    def fetch(self, cve_id):
        """Return a normalized EPSS observation, or None when unscored."""
        response = self.session.get(
            EPSS_API, params={"cve": cve_id}, timeout=self.timeout
        )
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            if getattr(exc.response, "status_code", None) == 404:
                return None
            raise
        payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise EPSSError("FIRST EPSS returned an invalid response envelope.")

        row = next(
            (
                item for item in payload["data"]
                if isinstance(item, dict)
                and str(item.get("cve") or "").upper() == cve_id.upper()
            ),
            None,
        )
        if row is None:
            return None
        try:
            score = float(row["epss"])
            percentile = float(row["percentile"])
        except (KeyError, TypeError, ValueError) as exc:
            raise EPSSError("FIRST EPSS returned an invalid score or percentile.") from exc
        if not 0 <= score <= 1 or not 0 <= percentile <= 1:
            raise EPSSError("FIRST EPSS score and percentile must be between 0 and 1.")

        score_date = str(row.get("date") or row.get("created") or "")
        retrieved_at = datetime.now(timezone.utc).isoformat()
        claims = {
            "epss": score,
            "percentile": percentile,
            "score_date": score_date or None,
            "interpretation": "estimated probability of exploitation activity in the next 30 days",
        }
        return {
            "source": "FIRST EPSS",
            "record_id": cve_id.upper(),
            "source_updated_at": score_date or None,
            "retrieved_at": retrieved_at,
            "trust_level": "authoritative",
            "review_status": "model estimate",
            "claims": claims,
            "payload": row,
        }
