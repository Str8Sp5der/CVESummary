"""
nvd_client.py — NVD CVE API client with MITRE/OSV enrichment and PoC lookups

Data sources:
  • NVD API 2.0    → CVE metadata, CVSS, affected systems
  • MITRE CVE API  → CNA/ADP metadata supplement and fallback
  • OSV.dev        → ecosystem package and affected-version supplement
  • GitHub Advisories → reviewed/unreviewed package advisory supplement
  • ExploitDB     → JSON search endpoint for known exploits
  • nomi-sec/PoC-in-GitHub → GitHub PoC index (raw JSON per CVE)
"""

import re
import time
import threading
import logging
import requests
import bleach
from datetime import datetime, timedelta, timezone

log = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITRE_CVE_API = "https://cveawg.mitre.org/api/cve"
OSV_API = "https://api.osv.dev/v1/vulns"
GITHUB_ADVISORY_API = "https://api.github.com/advisories"
REDHAT_CVE_API = "https://access.redhat.com/hydra/rest/securitydata/cve"
CISA_KEV_FEED = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
NVD_PAGE_SIZE = 2000
EXPLOITDB_API  = "https://www.exploit-db.com/search"
POCGITHUB_RAW  = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve_id}.json"

_SAFE_ATTRS: dict = {"a": ["href", "rel"], "code": []}


class NVDUpdateError(RuntimeError):
    """Raised when an NVD sync is incomplete."""


class CISAKEVUpdateError(RuntimeError):
    """Raised when a CISA KEV catalog sync is incomplete."""


class CVEUpstreamError(RuntimeError):
    """Raised when upstream sources cannot answer a CVE request."""

    def __init__(self, message: str, sources: list[str] | None = None):
        super().__init__(message)
        self.sources = sources or []


def _sanitize(text: str, max_len: int = 4000) -> str:
    """Strip all HTML tags except safe inline elements, cap length."""
    clean = bleach.clean(str(text), tags=list(_SAFE_ATTRS.keys()), attributes=_SAFE_ATTRS)
    return clean[:max_len]


class NVDClient:
    def __init__(
        self, api_key: str | None = None, github_token: str | None = None
    ):
        self.api_key = api_key
        self.github_token = github_token
        self._kev_cache: dict[str, dict] | None = None
        self._kev_cache_fetched_at: datetime | None = None
        self._kev_cache_lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "CVESummary/1.0",
                "Accept": "application/json",
            }
        )

    def _nvd_headers(self) -> dict[str, str] | None:
        return {"apiKey": self.api_key} if self.api_key else None

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #
    def fetch_cve(self, cve_id: str) -> dict | None:
        """Fetch CVE records from registries, ecosystem databases, and vendors."""
        nvd_record = None
        mitre_record = None
        osv_record = None
        github_record = None
        redhat_record = None
        cisa_kev_record = None
        failed_sources = []
        attempted_sources = []
        try:
            attempted_sources.append("NVD")
            resp = self.session.get(
                NVD_API,
                params={"cveId": cve_id},
                headers=self._nvd_headers(),
                timeout=15,
            )
            payload = self._response_json(resp)
            if payload is not None:
                vulnerabilities = payload.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    raise ValueError("NVD response has an invalid vulnerabilities field.")
                nvd_cve = next(
                    (
                        item.get("cve")
                        for item in vulnerabilities
                        if isinstance(item, dict)
                        and isinstance(item.get("cve"), dict)
                        and item["cve"].get("id", "").upper() == cve_id.upper()
                    ),
                    None,
                )
                if nvd_cve:
                    nvd_record = self._parse_nvd(nvd_cve)
                else:
                    log.debug("NVD returned no matching record for %s", cve_id)
        except (requests.RequestException, ValueError) as exc:
            log.warning("NVD fetch failed for %s: %s", cve_id, exc)
            failed_sources.append("NVD")

        try:
            attempted_sources.append("MITRE")
            mitre_record = self._fetch_mitre_cve(cve_id)
        except (requests.RequestException, ValueError) as exc:
            log.warning("MITRE CVE record lookup failed for %s: %s", cve_id, exc)
            failed_sources.append("MITRE")

        try:
            attempted_sources.append("OSV")
            osv_record = self._fetch_osv_cve(cve_id)
        except (requests.RequestException, ValueError) as exc:
            log.warning("OSV vulnerability lookup failed for %s: %s", cve_id, exc)
            failed_sources.append("OSV")

        try:
            attempted_sources.append("GitHub Advisory")
            github_record = self._fetch_github_advisory(cve_id)
        except (requests.RequestException, ValueError) as exc:
            log.warning("GitHub Advisory lookup failed for %s: %s", cve_id, exc)
            failed_sources.append("GitHub Advisory")

        try:
            attempted_sources.append("Red Hat Security Data")
            redhat_record = self._fetch_redhat_cve(cve_id)
        except (requests.RequestException, ValueError) as exc:
            log.warning("Red Hat Security Data lookup failed for %s: %s", cve_id, exc)
            failed_sources.append("Red Hat Security Data")

        try:
            attempted_sources.append("CISA KEV")
            cisa_kev_record = self._fetch_cisa_kev(cve_id)
        except (requests.RequestException, ValueError) as exc:
            log.warning("CISA KEV lookup failed for %s: %s", cve_id, exc)
            failed_sources.append("CISA KEV")

        if nvd_record and mitre_record:
            parsed = self._merge_records(nvd_record, mitre_record)
        else:
            parsed = nvd_record or mitre_record
        if parsed and osv_record:
            parsed = self._merge_records(parsed, osv_record)
        elif not parsed:
            parsed = osv_record
        if parsed and redhat_record:
            parsed = self._merge_records(parsed, redhat_record)
        elif not parsed:
            parsed = redhat_record
        if parsed and github_record:
            parsed = self._merge_records(parsed, github_record)
        elif not parsed:
            parsed = github_record
        if parsed and cisa_kev_record:
            parsed = self._merge_records(parsed, cisa_kev_record)
        elif not parsed:
            parsed = cisa_kev_record

        if not parsed:
            if failed_sources:
                raise CVEUpstreamError(
                    "CVE sources are temporarily unavailable: "
                    + ", ".join(failed_sources)
                    + ". Please try again.",
                    attempted_sources,
                )
            return None

        parsed["sources_checked"] = attempted_sources
        source_details = {}
        source_records = {
            "NVD": nvd_record,
            "MITRE": mitre_record,
            "OSV": osv_record,
            "GitHub Advisory": github_record,
            "Red Hat Security Data": redhat_record,
            "CISA KEV": cisa_kev_record,
        }
        for record in source_records.values():
            if not record:
                continue
            for observation in record.get("source_records", []):
                observation["claims"] = self._source_claims(record, observation)
        for source, record in source_records.items():
            if record:
                details = record.get("source_details", [])
                if not details and source in {"NVD", "MITRE"}:
                    details = [
                        {
                            "source": source,
                            "trust_level": "authoritative",
                            "untrusted": False,
                        }
                    ]
                for detail in details:
                    key = (detail["source"], detail.get("advisory_id"))
                    source_details[key] = detail
            elif source in failed_sources:
                source_details[(source, None)] = {
                    "source": source,
                    "trust_level": "unknown",
                    "untrusted": False,
                    "status": "unavailable",
                }
            else:
                source_details[(source, None)] = {
                    "source": source,
                    "trust_level": "unknown",
                    "untrusted": False,
                    "status": "no_matching_record",
                }
        parsed["source_details"] = list(source_details.values())
        parsed["source_warnings"] = [
            f"{source} could not be reached; its metadata may be missing."
            for source in failed_sources
        ]
        fetched_at = datetime.now(timezone.utc).isoformat()
        parsed["source_records"] = [
            observation
            for record in source_records.values()
            if record
            for observation in record.get("source_records", [])
        ]
        for observation in parsed["source_records"]:
            observation.setdefault("retrieved_at", fetched_at)
        for detail in parsed["source_details"]:
            detail["last_checked_at"] = fetched_at
            provider = next(
                (
                    source
                    for source in source_records
                    if source in detail.get("source", "")
                ),
                None,
            )
            matching_observations = [
                observation
                for observation in parsed["source_records"]
                if provider and observation["source"] == provider
            ]
            advisory_id = detail.get("advisory_id")
            if advisory_id:
                matching_observations = [
                    observation
                    for observation in matching_observations
                    if observation["record_id"] == advisory_id
                ]
            if matching_observations:
                observation = matching_observations[-1]
                detail["source_updated_at"] = observation.get("source_updated_at")
                if observation.get("review_status"):
                    detail["review_status"] = observation["review_status"]
        parsed["poc"] = self._collect_poc(cve_id)
        return parsed

    @staticmethod
    def _response_json(resp: requests.Response) -> dict | None:
        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            if getattr(exc.response, "status_code", None) == 404:
                return None
            raise
        payload = resp.json()
        if not isinstance(payload, dict):
            raise ValueError("Upstream response must be a JSON object.")
        return payload

    @staticmethod
    def _source_observation(
        source: str,
        record_id: str,
        payload: dict | list,
        source_updated_at: str = "",
        trust_level: str = "unknown",
        review_status: str = "",
        claims: dict | None = None,
    ) -> dict:
        return {
            "source": source,
            "record_id": str(record_id),
            "source_updated_at": source_updated_at or None,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "trust_level": trust_level,
            "review_status": review_status or None,
            "claims": claims or {},
            "payload": payload,
        }

    @staticmethod
    def _source_claims(record: dict, observation: dict | None = None) -> dict:
        if (
            observation
            and observation.get("source") == "GitHub Advisory"
            and isinstance(observation.get("payload"), dict)
        ):
            advisory = observation["payload"]
            cvss_data = advisory.get("cvss") or {}
            vector = cvss_data.get("vector_string") or ""
            version = (
                "cvss_v4"
                if vector.startswith("CVSS:4.")
                else "cvss_v3"
                if vector.startswith("CVSS:3.")
                else "cvss_v2"
                if vector.startswith("CVSS:2.")
                else None
            )
            cvss = {}
            if version and cvss_data.get("score") is not None:
                cvss[version] = {
                    "score": cvss_data["score"],
                    "severity": str(advisory.get("severity") or "UNKNOWN").upper(),
                    "vector": vector,
                    "source": "GitHub Advisory",
                    "trust_level": (
                        "curated"
                        if str(advisory.get("type") or "").lower() == "reviewed"
                        else "unverified"
                    ),
                    "untrusted": str(advisory.get("type") or "").lower()
                    != "reviewed",
                }
            return {
                "description": advisory.get("description") or advisory.get("summary") or "",
                "cvss": cvss,
                "affected_count": len(advisory.get("vulnerabilities") or []),
            }

        cvss = {
            version: record[version]
            for version in ("cvss_v4", "cvss_v3", "cvss_v2")
            if record.get(version)
        }
        return {
            "description": record.get("description") or "",
            "cvss": cvss,
            "affected_count": len(record.get("affected_systems") or []),
        }

    def _get_cisa_kev_catalog(self, force_refresh: bool = False) -> dict[str, dict]:
        now = datetime.now(timezone.utc)
        with self._kev_cache_lock:
            cache_is_fresh = (
                self._kev_cache is not None
                and self._kev_cache_fetched_at is not None
                and now - self._kev_cache_fetched_at < timedelta(hours=6)
            )
            if force_refresh or not cache_is_fresh:
                resp = self.session.get(CISA_KEV_FEED, timeout=20)
                payload = self._response_json(resp)
                if payload is None:
                    raise ValueError("CISA KEV feed returned no catalog.")
                vulnerabilities = payload.get("vulnerabilities")
                if not isinstance(vulnerabilities, list):
                    raise ValueError("CISA KEV feed has an invalid vulnerabilities field.")
                records = {}
                for item in vulnerabilities:
                    if not isinstance(item, dict):
                        raise ValueError("CISA KEV feed contains an invalid entry.")
                    identifier = item.get("cveID")
                    if not isinstance(identifier, str) or not re.fullmatch(
                        r"CVE-\d{4}-\d{4,}", identifier, flags=re.IGNORECASE
                    ):
                        raise ValueError("CISA KEV feed contains an invalid CVE ID.")
                    records[identifier.upper()] = item
                self._kev_cache = records
                self._kev_cache_fetched_at = now
            return dict(self._kev_cache or {})

    def _fetch_cisa_kev(self, cve_id: str) -> dict | None:
        vulnerability = self._get_cisa_kev_catalog().get(cve_id.upper())

        if not vulnerability:
            return None

        return self._fetch_cisa_kev_record(cve_id, vulnerability)

    def sync_cisa_kev(self, db) -> int:
        """Mirror the CISA KEV catalog into the local CVE store."""
        started_at = datetime.now(timezone.utc).isoformat()
        count = 0
        try:
            catalog = self._get_cisa_kev_catalog(force_refresh=True)
            stale_ids = set(db.get_cve_ids_with_kev()) - set(catalog)
            for cve_id, vulnerability in catalog.items():
                record = self._fetch_cisa_kev_record(cve_id, vulnerability)
                db.store_cve(record)
                count += 1
            checked_at = datetime.now(timezone.utc).isoformat()
            for cve_id in stale_ids:
                cached = db.get_cve(cve_id)
                if not cached:
                    continue
                cached["cisa_kev"] = None
                cached["sources_checked"] = list(
                    dict.fromkeys((cached.get("sources_checked") or []) + ["CISA KEV"])
                )
                cached["source_details"] = [
                    detail
                    for detail in (cached.get("source_details") or [])
                    if not isinstance(detail, dict)
                    or detail.get("source") != "CISA KEV"
                ] + [
                    {
                        "source": "CISA KEV",
                        "trust_level": "authoritative",
                        "untrusted": False,
                        "status": "no_matching_record",
                        "last_checked_at": checked_at,
                    }
                ]
                cached["refs"] = [
                    ref
                    for ref in (cached.get("refs") or [])
                    if not (
                        isinstance(ref, dict)
                        and "CISA KEV" in (ref.get("sources") or [ref.get("source")])
                    )
                ]
                cached["source_records"] = [
                    self._source_observation(
                        "CISA KEV",
                        cve_id,
                        {"cveID": cve_id, "status": "removed from current catalog"},
                        trust_level="authoritative",
                        review_status="not listed in current KEV catalog",
                        claims={"description": "", "cvss": {}, "affected_count": 0},
                    )
                ]
                cached["fetched_at"] = checked_at
                db.store_cve(cached)
                count += 1
        except (requests.RequestException, ValueError) as exc:
            db.log_source_sync(
                "CISA KEV", started_at, False, count, str(exc)
            )
            raise CISAKEVUpdateError(
                f"CISA KEV sync was incomplete; stored {count} CVEs."
            ) from exc

        db.log_source_sync("CISA KEV", started_at, True, count)
        log.info("CISA KEV sync: stored %d CVEs", count)
        return count

    def _fetch_cisa_kev_record(self, cve_id: str, vulnerability: dict) -> dict:
        now = datetime.now(timezone.utc)
        source_name = "CISA KEV"
        return {
            "id": cve_id,
            "description": str(vulnerability.get("vulnerabilityName") or ""),
            "published": "",
            "modified": "",
            "cvss_v4": None,
            "cvss_v3": None,
            "cvss_v2": None,
            "affected_systems": [],
            "refs": [
                {
                    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "source": source_name,
                    "sources": [source_name],
                    "tags": [],
                    "trust_level": "authoritative",
                    "untrusted": False,
                }
            ],
            "cwes": [],
            "cisa_kev": {
                "source": source_name,
                "date_added": vulnerability.get("dateAdded", ""),
                "due_date": vulnerability.get("dueDate", ""),
                "known_ransomware_campaign_use": vulnerability.get(
                    "knownRansomwareCampaignUse", ""
                ),
                "required_action": vulnerability.get("requiredAction", ""),
                "notes": vulnerability.get("notes", ""),
                "vulnerability_name": vulnerability.get("vulnerabilityName", ""),
                "vendor_project": vulnerability.get("vendorProject", ""),
                "product": vulnerability.get("product", ""),
            },
            "ssvc": [],
            "poc": [],
            "source": source_name,
            "source_details": [
                {
                    "source": source_name,
                    "trust_level": "authoritative",
                    "untrusted": False,
                    "last_checked_at": now.isoformat(),
                }
            ],
            "sources_checked": [source_name],
            "source_warnings": [],
            "fetched_at": now.isoformat(),
            "source_records": [
                self._source_observation(
                    source_name,
                    cve_id,
                    vulnerability,
                    trust_level="authoritative",
                    review_status="included in KEV",
                    claims={
                        "description": str(vulnerability.get("vulnerabilityName") or ""),
                        "cvss": {},
                        "affected_count": 0,
                    },
                )
            ],
        }

    def _fetch_mitre_cve(self, cve_id: str) -> dict | None:
        resp = self.session.get(f"{MITRE_CVE_API}/{cve_id}", timeout=15)
        data = self._response_json(resp)
        if not data:
            return None
        if data.get("cveMetadata", {}).get("cveId", "").upper() != cve_id.upper():
            log.warning("MITRE returned no matching record for %s", cve_id)
            return None
        parsed = self._parse_mitre(data)
        parsed["source_records"] = [
            self._source_observation(
                "MITRE",
                cve_id,
                data,
                source_updated_at=data.get("cveMetadata", {}).get("dateUpdated", ""),
                trust_level="authoritative",
                review_status=data.get("cveMetadata", {}).get("state", ""),
            )
        ]
        return parsed

    def _fetch_osv_cve(self, cve_id: str) -> dict | None:
        resp = self.session.get(f"{OSV_API}/{cve_id}", timeout=15)
        data = self._response_json(resp)
        if not data:
            return None
        if not isinstance(data.get("aliases", []), list):
            raise ValueError("OSV response has an invalid aliases field.")
        identifiers = [data.get("id", ""), *data.get("aliases", [])]
        if cve_id.upper() not in {identifier.upper() for identifier in identifiers}:
            log.warning("OSV returned no matching record for %s", cve_id)
            return None

        affected = self._extract_osv_affected(data.get("affected", []))
        if not isinstance(data.get("references", []), list):
            raise ValueError("OSV response has an invalid references field.")
        refs = [
            {
                "url": _sanitize(ref["url"], 512),
                "source": "OSV",
                "sources": ["OSV"],
                "tags": [],
                "trust_level": "secondary",
                "untrusted": False,
            }
            for ref in data.get("references", [])
            if isinstance(ref, dict) and ref.get("url")
        ]
        return {
            "id": cve_id,
            "description": _sanitize(data.get("details") or data.get("summary") or ""),
            "published": data.get("published", ""),
            "modified": data.get("modified", ""),
            "cvss_v4": None,
            "cvss_v3": None,
            "cvss_v2": None,
            "affected_systems": affected,
            "refs": refs,
            "cwes": [],
            "cisa_kev": None,
            "ssvc": [],
            "poc": [],
            "source": "OSV",
            "source_details": [
                {
                    "source": "OSV",
                    "trust_level": "secondary",
                    "untrusted": False,
                }
            ],
            "sources_checked": ["OSV"],
            "source_warnings": [],
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "source_records": [
                self._source_observation(
                    "OSV",
                    str(data.get("id") or cve_id),
                    data,
                    source_updated_at=data.get("modified", ""),
                    trust_level="secondary",
                )
            ],
        }

    def _fetch_redhat_cve(self, cve_id: str) -> dict | None:
        resp = self.session.get(
            f"{REDHAT_CVE_API}/{cve_id}.json",
            timeout=15,
        )
        data = self._response_json(resp)
        if data is None:
            return None
        if str(data.get("name") or "").upper() != cve_id.upper():
            return None

        source_name = "Red Hat Security Data"
        severity_names = {
            "critical": "CRITICAL",
            "important": "HIGH",
            "moderate": "MEDIUM",
            "low": "LOW",
        }
        severity = severity_names.get(
            str(data.get("threat_severity") or "").lower(),
            "UNKNOWN",
        )
        cvss_metrics = {}
        for field, score_field, vector_field, version in (
            ("cvss3", "cvss3_base_score", "cvss3_scoring_vector", "cvss_v3"),
            ("cvss", "cvss_base_score", "cvss_scoring_vector", "cvss_v2"),
        ):
            metric = data.get(field)
            if not isinstance(metric, dict) or metric.get(score_field) is None:
                continue
            try:
                score = float(metric[score_field])
            except (TypeError, ValueError):
                continue
            verified = str(metric.get("status") or "").lower() == "verified"
            cvss_metrics[version] = {
                "score": score,
                "severity": severity,
                "vector": metric.get(vector_field) or "",
                "source": source_name,
                "trust_level": "authoritative" if verified else "unverified",
                "untrusted": not verified,
            }

        source_details = [
            {
                "source": source_name,
                "trust_level": "authoritative",
                "untrusted": False,
                "record_type": "vendor",
            }
        ]
        affected = []
        package_states = data.get("package_state") or []
        if not isinstance(package_states, list):
            raise ValueError("Red Hat CVE record has an invalid package_state field.")
        affected_states = {"affected", "fix deferred", "will not fix"}
        for package_state in package_states:
            if not isinstance(package_state, dict):
                continue
            fix_state = str(package_state.get("fix_state") or "")
            normalized_state = fix_state.lower()
            status = (
                "affected"
                if normalized_state in affected_states
                else "unaffected"
                if normalized_state == "not affected"
                else "unknown"
            )
            package_name = package_state.get("package_name") or ""
            affected.append(
                {
                    "vendor": "Red Hat",
                    "product": package_state.get("product_name") or package_name,
                    "version": (
                        f"{package_name} ({fix_state})"
                        if package_name and fix_state
                        else package_name or fix_state
                    ),
                    "version_start": None,
                    "version_end": None,
                    "version_range": "",
                    "patched_version": None,
                    "version_type": "Red Hat package",
                    "status": status,
                    "vendor_status": fix_state,
                    "cpe": package_state.get("cpe") or "",
                    "source": source_name,
                    "trust_level": "authoritative",
                    "untrusted": False,
                }
            )

        references = [
            {
                "url": f"{REDHAT_CVE_API}/{cve_id}.json",
                "source": source_name,
                "sources": [source_name],
                "tags": [],
                "trust_level": "authoritative",
                "untrusted": False,
            }
        ]
        affected_releases = data.get("affected_release") or []
        if not isinstance(affected_releases, list):
            raise ValueError("Red Hat CVE record has an invalid affected_release field.")
        for release in affected_releases:
            if not isinstance(release, dict):
                continue
            advisory = str(release.get("advisory") or "")
            product = release.get("product_name") or ""
            package = release.get("package") or ""
            affected.append(
                {
                    "vendor": "Red Hat",
                    "product": product,
                    "version": package or product,
                    "version_start": None,
                    "version_end": None,
                    "version_range": "",
                    "patched_version": package or None,
                    "version_type": "Red Hat release",
                    "status": "fixed",
                    "release_date": release.get("release_date") or "",
                    "advisory": advisory,
                    "cpe": release.get("cpe") or "",
                    "source": source_name,
                    "trust_level": "authoritative",
                    "untrusted": False,
                }
            )
            if advisory:
                references.append(
                    {
                        "url": f"https://access.redhat.com/errata/{advisory}",
                        "source": source_name,
                        "sources": [source_name],
                        "tags": [],
                        "trust_level": "authoritative",
                        "untrusted": False,
                    }
                )

        raw_references = data.get("references") or []
        if isinstance(raw_references, list):
            for reference in raw_references:
                urls = reference.splitlines() if isinstance(reference, str) else []
                for url in urls:
                    url = url.strip()
                    if url.startswith(("https://", "http://")):
                        references.append(
                            {
                                "url": url,
                                "source": source_name,
                                "sources": [source_name],
                                "tags": [],
                                "trust_level": "authoritative",
                                "untrusted": False,
                            }
                        )

        details = data.get("details") or []
        if isinstance(details, str):
            details = [details]
        if not isinstance(details, list):
            raise ValueError("Red Hat CVE record has an invalid details field.")
        description = " ".join(
            detail for detail in details if isinstance(detail, str) and detail
        )
        if not description:
            description = str(data.get("statement") or "")
        cwes = data.get("cwe") or []
        if isinstance(cwes, str):
            cwes = [cwes]
        elif not isinstance(cwes, list):
            cwes = []

        return {
            "id": cve_id,
            "description": _sanitize(description),
            "published": data.get("public_date") or "",
            "modified": data.get("modified_date") or "",
            "cvss_v4": None,
            "cvss_v3": cvss_metrics.get("cvss_v3"),
            "cvss_v2": cvss_metrics.get("cvss_v2"),
            "affected_systems": affected,
            "refs": references,
            "cwes": cwes,
            "cisa_kev": None,
            "ssvc": [],
            "poc": [],
            "source": source_name,
            "source_details": source_details,
            "sources_checked": [source_name],
            "source_warnings": [],
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "source_records": [
                self._source_observation(
                    source_name,
                    cve_id,
                    data,
                    source_updated_at=data.get("modified_date", ""),
                    trust_level="authoritative",
                    review_status="vendor advisory",
                )
            ],
        }

    def _fetch_github_advisory(self, cve_id: str) -> dict | None:
        resp = self.session.get(
            GITHUB_ADVISORY_API,
            params={"cve_id": cve_id, "per_page": 100},
            headers=(
                {"Authorization": f"Bearer {self.github_token}"}
                if self.github_token
                else None
            ),
            timeout=15,
        )
        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            if getattr(exc.response, "status_code", None) == 404:
                return None
            raise
        advisories = resp.json()
        if not isinstance(advisories, list):
            raise ValueError("GitHub Advisory response must be a JSON list.")

        matching = [
            advisory
            for advisory in advisories
            if isinstance(advisory, dict)
            and str(advisory.get("cve_id") or "").upper() == cve_id.upper()
        ]
        if not matching:
            return None

        affected = []
        refs = []
        source_details = []
        descriptions = []
        cvss_candidates = []
        published_dates = []
        modified_dates = []
        for advisory in matching:
            advisory_type = str(advisory.get("type") or "").lower()
            reviewed = advisory_type == "reviewed"
            trust_level = "curated" if reviewed else "unverified"
            source_name = "GitHub Advisory"
            if not reviewed:
                status_label = "unreviewed" if advisory_type == "unreviewed" else "unverified"
                source_name += f" ({status_label})"

            source_details.append(
                {
                    "source": source_name,
                    "trust_level": trust_level,
                    "untrusted": not reviewed,
                    "record_type": advisory_type or "unknown",
                    "advisory_id": advisory.get("ghsa_id"),
                }
            )
            description = advisory.get("description") or advisory.get("summary")
            if description:
                descriptions.append(description)
            if advisory.get("published_at"):
                published_dates.append(advisory["published_at"])
            if advisory.get("updated_at"):
                modified_dates.append(advisory["updated_at"])

            vulnerabilities = advisory.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                raise ValueError("GitHub Advisory has an invalid vulnerabilities field.")
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue
                package = vulnerability.get("package") or {}
                if not isinstance(package, dict) or not package.get("name"):
                    continue
                ecosystem = package.get("ecosystem", "")
                version_range = vulnerability.get("vulnerable_version_range", "")
                patched = vulnerability.get("first_patched_version")
                if isinstance(patched, dict):
                    patched_version = patched.get("identifier")
                elif isinstance(patched, str):
                    patched_version = patched
                else:
                    patched_version = None
                affected.append(
                    {
                        "vendor": ecosystem or "Unknown",
                        "product": package["name"],
                        "version": version_range or "Version range not provided",
                        "version_start": None,
                        "version_end": None,
                        "version_range": version_range,
                        "patched_version": patched_version,
                        "version_type": ecosystem,
                        "status": "affected",
                        "cpe": "",
                        "source": source_name,
                        "trust_level": trust_level,
                        "untrusted": not reviewed,
                    }
                )

            cvss_data = advisory.get("cvss") or {}
            if not isinstance(cvss_data, dict):
                raise ValueError("GitHub Advisory has an invalid CVSS field.")
            vector = cvss_data.get("vector_string") or ""
            version = (
                "cvss_v4"
                if vector.startswith("CVSS:4.")
                else "cvss_v3"
                if vector.startswith("CVSS:3.")
                else "cvss_v2"
                if vector.startswith("CVSS:2.")
                else None
            )
            if version and cvss_data.get("score") is not None:
                cvss_candidates.append(
                    (
                        not reviewed,
                        version,
                        {
                            "score": cvss_data["score"],
                            "severity": str(advisory.get("severity") or "UNKNOWN").upper(),
                            "vector": vector,
                            "source": source_name,
                            "trust_level": trust_level,
                            "untrusted": not reviewed,
                        },
                    )
                )
            if advisory.get("html_url"):
                refs.append(
                    {
                        "url": _sanitize(advisory["html_url"], 512),
                        "source": source_name,
                        "sources": ["GitHub Advisory"],
                        "tags": [],
                        "trust_level": trust_level,
                        "untrusted": not reviewed,
                    }
                )

        cvss_by_version = {}
        for _, version, cvss in sorted(cvss_candidates, key=lambda item: item[0]):
            cvss_by_version.setdefault(version, cvss)
        source_names = list(dict.fromkeys(detail["source"] for detail in source_details))
        combined_source = " + ".join(source_names)
        return {
            "id": cve_id,
            "description": _sanitize(descriptions[0]) if descriptions else "",
            "published": min(published_dates) if published_dates else "",
            "modified": max(modified_dates) if modified_dates else "",
            "cvss_v4": cvss_by_version.get("cvss_v4"),
            "cvss_v3": cvss_by_version.get("cvss_v3"),
            "cvss_v2": cvss_by_version.get("cvss_v2"),
            "affected_systems": affected,
            "refs": refs,
            "cwes": [],
            "cisa_kev": None,
            "ssvc": [],
            "poc": [],
            "source": combined_source,
            "source_details": source_details,
            "sources_checked": ["GitHub Advisory"],
            "source_warnings": [],
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "source_records": [
                self._source_observation(
                    "GitHub Advisory",
                    str(advisory.get("ghsa_id") or cve_id),
                    advisory,
                    source_updated_at=advisory.get("updated_at", ""),
                    trust_level=(
                        "curated"
                        if str(advisory.get("type") or "").lower() == "reviewed"
                        else "unverified"
                    ),
                    review_status=str(advisory.get("type") or "unknown"),
                )
                for advisory in matching
            ],
        }

    @staticmethod
    def _merge_records(nvd_record: dict, mitre_record: dict) -> dict:
        """Prefer NVD metrics and combine complementary CVE-record metadata."""
        merged = dict(nvd_record)
        merged["source_records"] = (
            nvd_record.get("source_records", [])
            + mitre_record.get("source_records", [])
        )
        for field in ("cvss_v4", "cvss_v3", "cvss_v2"):
            primary_metric = nvd_record.get(field)
            secondary_metric = mitre_record.get(field)
            if (
                primary_metric
                and primary_metric.get("untrusted")
                and secondary_metric
                and not secondary_metric.get("untrusted")
            ):
                primary_metric = secondary_metric
            merged[field] = primary_metric or secondary_metric

        key_fields = (
            "cpe",
            "vendor",
            "product",
            "version",
            "version_range",
            "patched_version",
            "status",
            "url",
        )

        def metadata_key(value):
            if isinstance(value, dict):
                return tuple(value.get(key) for key in key_fields)
            return value

        for field in ("affected_systems", "refs", "cwes"):
            values = []
            seen = set()
            for value in nvd_record.get(field, []) + mitre_record.get(field, []):
                key = metadata_key(value)
                if key not in seen:
                    seen.add(key)
                    values.append(value)
                elif field == "affected_systems":
                    existing = next(
                        item for item in values if metadata_key(item) == key
                    )
                    sources = existing.setdefault(
                        "sources",
                        [existing["source"]] if existing.get("source") else [],
                    )
                    source = value.get("source", "")
                    if source and source not in sources:
                        sources.append(source)
                    existing["untrusted"] = bool(
                        existing.get("untrusted") or value.get("untrusted")
                    )
                    if existing["untrusted"]:
                        existing["trust_level"] = "unverified"
                elif field == "refs" and isinstance(value, dict):
                    existing = next(
                        item for item in values if metadata_key(item) == key
                    )
                    sources = existing.setdefault(
                        "sources",
                        [existing["source"]] if existing.get("source") else [],
                    )
                    incoming_sources = value.get("sources") or (
                        [value["source"]] if value.get("source") else []
                    )
                    for source in incoming_sources:
                        if source and source not in sources:
                            sources.append(source)
                    existing["untrusted"] = bool(
                        existing.get("untrusted") or value.get("untrusted")
                    )
                    if existing["untrusted"]:
                        existing["trust_level"] = "unverified"
            merged[field] = values

        if merged.get("description") == "No description available.":
            merged["description"] = mitre_record.get("description", merged["description"])
        for field in ("published", "modified"):
            merged[field] = nvd_record.get(field) or mitre_record.get(field, "")

        if mitre_record.get("source") == "CISA KEV":
            merged["cisa_kev"] = mitre_record.get("cisa_kev") or nvd_record.get("cisa_kev")
        else:
            merged["cisa_kev"] = nvd_record.get("cisa_kev") or mitre_record.get("cisa_kev")
        merged["ssvc"] = nvd_record.get("ssvc") or mitre_record.get("ssvc", [])
        sources = list(dict.fromkeys(
            source
            for record in (nvd_record, mitre_record)
            for source in record.get("source", "").split(" + ")
            if source
        ))
        if sources:
            merged["source"] = " + ".join(sources)
        return merged

    @staticmethod
    def cache_needs_refresh(cve: dict, now: datetime | None = None) -> bool:
        """Refresh records missing a source check; retry incomplete data daily."""
        has_cvss = any(cve.get(field) for field in ("cvss_v4", "cvss_v3", "cvss_v2"))
        affected = cve.get("affected_systems") or []
        has_precise_ranges = all(
            item.get("version_range")
            or not (item.get("version_start") or item.get("version_end"))
            for item in affected
        )
        has_affected_versions = any(
            item.get("status") != "unaffected" for item in affected
        )
        if not has_precise_ranges:
            return True
        sources_checked = set(cve.get("sources_checked") or [])
        required_sources = {
            "OSV",
            "GitHub Advisory",
            "Red Hat Security Data",
            "CISA KEV",
        }
        if not required_sources.issubset(sources_checked):
            return True
        if has_cvss and has_affected_versions and not cve.get("source_warnings"):
            return False

        try:
            fetched_at = datetime.fromisoformat(cve.get("fetched_at", ""))
            if fetched_at.tzinfo is None:
                fetched_at = fetched_at.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return True

        now = now or datetime.now(timezone.utc)
        return now - fetched_at >= timedelta(hours=24)

    def search_cves(self, query: str, limit: int = 8) -> tuple[list[dict], int]:
        """Search NVD by keyword and return the most recently published matches."""
        params = {"keywordSearch": query, "resultsPerPage": limit}
        try:
            resp = self.session.get(
                NVD_API,
                params=params,
                headers=self._nvd_headers(),
                timeout=20,
            )
            payload = self._response_json(resp)
            if not payload:
                return [], 0
            total_results = int(payload.get("totalResults", 0))
            vulnerabilities = payload.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                raise ValueError("NVD search response has an invalid vulnerabilities field.")

            if total_results > limit:
                params["startIndex"] = max(0, total_results - limit)
                resp = self.session.get(
                    NVD_API,
                    params=params,
                    headers=self._nvd_headers(),
                    timeout=20,
                )
                payload = self._response_json(resp)
                if not payload:
                    raise ValueError("NVD returned no results for the search page.")
                vulnerabilities = payload.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    raise ValueError(
                        "NVD search response has an invalid vulnerabilities field."
                    )
        except (requests.RequestException, ValueError) as exc:
            raise CVEUpstreamError(
                "NVD keyword search is temporarily unavailable. Please try again."
            ) from exc

        results = []
        for item in vulnerabilities:
            cve = item.get("cve", {}) if isinstance(item, dict) else {}
            if not isinstance(cve, dict) or not cve.get("id"):
                continue
            parsed = self._parse_nvd(cve)
            cvss = parsed.get("cvss_v4") or parsed.get("cvss_v3") or parsed.get("cvss_v2") or {}
            results.append(
                {
                    "id": parsed["id"],
                    "description": parsed["description"],
                    "published": parsed["published"],
                    "severity": cvss.get("severity", "UNKNOWN"),
                    "cvss_score": cvss.get("score", 0),
                    "source": "NVD",
                }
            )
        results.sort(key=lambda result: result["published"] or "", reverse=True)
        return results, total_results

    def update_recent_cves(self, db, days_back: int = 1) -> int:
        """Store CVEs modified in the last N days using the paginated NVD API."""
        if not 1 <= days_back <= 120:
            raise ValueError("days_back must be between 1 and 120 for the NVD API.")

        now = datetime.now(timezone.utc)
        started_at = now.isoformat()
        start = now - timedelta(days=days_back)
        date_params = {
            "lastModStartDate": start.isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
            "lastModEndDate": now.isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
        }
        start_index = 0
        count = 0
        success = True

        while True:
            try:
                if start_index:
                    time.sleep(0.7 if self.api_key else 6.1)
                resp = self.session.get(
                    NVD_API,
                    params={
                        **date_params,
                        "startIndex": start_index,
                        "resultsPerPage": NVD_PAGE_SIZE,
                    },
                    headers=self._nvd_headers(),
                    timeout=30,
                )
                resp.raise_for_status()
                payload = resp.json()
                vulnerabilities = payload.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    raise ValueError("NVD response has an invalid vulnerabilities field.")
                total_results = int(
                    payload.get("totalResults", start_index + len(vulnerabilities))
                )
            except Exception as exc:
                log.error("NVD bulk fetch failed at index %d: %s", start_index, exc)
                success = False
                break

            for item in vulnerabilities:
                try:
                    cve = item.get("cve") if isinstance(item, dict) else None
                    if not isinstance(cve, dict):
                        raise ValueError("NVD response contains an invalid CVE record.")
                    parsed = self._parse_nvd(cve)
                    db.store_cve(parsed)
                    count += 1
                except Exception as exc:
                    cve = item.get("cve") if isinstance(item, dict) else None
                    cve_id = (
                        cve.get("id", "unknown")
                        if isinstance(cve, dict)
                        else "unknown"
                    )
                    log.warning("Skipped %s during NVD sync: %s", cve_id, exc)
                    success = False

            start_index += len(vulnerabilities)
            if not vulnerabilities or start_index >= total_results:
                break

        db.log_update(count, success=success)
        db.log_source_sync(
            "NVD",
            started_at,
            success,
            count,
            None if success else f"NVD sync was incomplete; stored {count} CVEs.",
        )
        log.info("NVD sync: stored %d CVEs (success=%s)", count, success)
        if not success:
            raise NVDUpdateError(f"NVD sync was incomplete; stored {count} CVEs.")
        return count

    def sync_nvd_full(self, db) -> int:
        """Seed the local store from every CVE record exposed by NVD."""
        started_at = datetime.now(timezone.utc).isoformat()
        start_index = 0
        count = 0
        success = True
        total_results = None

        while total_results is None or start_index < total_results:
            try:
                if start_index:
                    time.sleep(0.7 if self.api_key else 6.1)
                resp = self.session.get(
                    NVD_API,
                    params={
                        "startIndex": start_index,
                        "resultsPerPage": NVD_PAGE_SIZE,
                    },
                    headers=self._nvd_headers(),
                    timeout=30,
                )
                resp.raise_for_status()
                payload = resp.json()
                if not isinstance(payload, dict) or "totalResults" not in payload:
                    raise ValueError("NVD response is missing catalog metadata.")
                vulnerabilities = payload.get("vulnerabilities")
                if not isinstance(vulnerabilities, list):
                    raise ValueError("NVD response has an invalid vulnerabilities field.")
                total_results = int(payload["totalResults"])
                if not vulnerabilities and start_index < total_results:
                    raise ValueError("NVD returned an empty page before the end of the catalog.")
            except (requests.RequestException, ValueError, TypeError) as exc:
                success = False
                log.error("NVD full sync failed at index %d: %s", start_index, exc)
                break

            for item in vulnerabilities:
                try:
                    cve = item.get("cve") if isinstance(item, dict) else None
                    if not isinstance(cve, dict) or not cve.get("id"):
                        raise ValueError("NVD response contains an invalid CVE record.")
                    db.store_cve(self._parse_nvd(cve))
                    count += 1
                except (ValueError, TypeError, KeyError) as exc:
                    success = False
                    log.warning("Skipped invalid NVD record at index %d: %s", start_index, exc)

            start_index += len(vulnerabilities)

        db.log_update(count, success=success)
        db.log_source_sync(
            "NVD",
            started_at,
            success,
            count,
            None if success else f"NVD full sync was incomplete; stored {count} CVEs.",
        )
        log.info("NVD full sync: stored %d CVEs (success=%s)", count, success)
        if not success:
            raise NVDUpdateError(f"NVD full sync was incomplete; stored {count} CVEs.")
        return count

    # ------------------------------------------------------------------ #
    # NVD Parsing                                                          #
    # ------------------------------------------------------------------ #
    def _parse_nvd(self, cve: dict) -> dict:
        cve_id = cve.get("id", "")

        # --- Description (English preferred) ---
        descs = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descs if d.get("lang") == "en"),
            "No description available.",
        )

        # --- CVSS ---
        metrics = cve.get("metrics", {})
        cvss_v4 = self._extract_nvd_cvss(metrics, "cvssMetricV40")
        cvss_v3 = self._extract_cvssv3(metrics)
        cvss_v2 = self._extract_cvssv2(metrics)

        # --- Affected Systems (CPE) ---
        affected = self._extract_cpe(cve.get("configurations", []))

        # --- References ---
        refs = [
            {
                "url":    _sanitize(r["url"], 512),
                "source": _sanitize(r.get("source", ""), 64),
                "sources": ["NVD"],
                "tags":   r.get("tags", []),
            }
            for r in cve.get("references", [])
            if r.get("url")
        ]

        # --- CWE ---
        cwes = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("lang") == "en":
                    cwes.append(d["value"])

        return {
            "id":               cve_id,
            "description":      _sanitize(description),
            "published":        cve.get("published", ""),
            "modified":         cve.get("lastModified", ""),
            "cvss_v4":          cvss_v4,
            "cvss_v3":          cvss_v3,
            "cvss_v2":          cvss_v2,
            "affected_systems": affected,
            "refs":             refs,
            "cwes":             cwes,
            "cisa_kev":         None,
            "ssvc":             [],
            "poc":              [],          # filled later
            "source":           "NVD",
            "source_details": [
                {
                    "source": "NVD",
                    "trust_level": "authoritative",
                    "untrusted": False,
                }
            ],
            "sources_checked":  ["NVD"],
            "source_warnings":  [],
            "fetched_at":       datetime.now(timezone.utc).isoformat(),
            "source_records": [
                self._source_observation(
                    "NVD",
                    cve_id,
                    cve,
                    source_updated_at=cve.get("lastModified", ""),
                    trust_level="authoritative",
                    review_status=cve.get("vulnStatus", ""),
                    claims={
                        "description": _sanitize(description),
                        "cvss": {
                            version: metric
                            for version, metric in (
                                ("cvss_v4", cvss_v4),
                                ("cvss_v3", cvss_v3),
                                ("cvss_v2", cvss_v2),
                            )
                            if metric
                        },
                        "affected_count": len(affected),
                    },
                )
            ],
        }

    def _parse_mitre(self, data: dict) -> dict:
        cve_id = data.get("cveMetadata", {}).get("cveId", "")

        containers = data.get("containers", {})
        cna = containers.get("cna", {})
        adp = containers.get("adp", [])

        # Description
        descriptions = cna.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available.",
        )

        # Published and Modified
        published = data.get("cveMetadata", {}).get("datePublished", "")
        modified = data.get("cveMetadata", {}).get("dateUpdated", "")

        cvss_v4 = self._extract_mitre_cvss(cna.get("metrics", []), "cvssV4_0")
        cvss_v3 = self._extract_mitre_cvss(cna.get("metrics", []), "cvssV3_1")
        cvss_v3 = cvss_v3 or self._extract_mitre_cvss(
            cna.get("metrics", []), "cvssV3_0"
        )
        cvss_v2 = self._extract_mitre_cvss(cna.get("metrics", []), "cvssV2_0")
        affected = self._extract_mitre_affected(cna.get("affected", []))

        cisa_kev = None
        ssvc = []
        for provider in adp:
            short_name = provider.get("providerMetadata", {}).get("shortName", "")
            for metric in provider.get("metrics", []):
                adp_source = f"{short_name} ADP" if short_name else "MITRE ADP"
                cvss_v4 = cvss_v4 or self._extract_mitre_metric(
                    metric, "cvssV4_0", adp_source
                )
                cvss_v3 = cvss_v3 or self._extract_mitre_metric(
                    metric, "cvssV3_1", adp_source
                )
                cvss_v3 = cvss_v3 or self._extract_mitre_metric(
                    metric, "cvssV3_0", adp_source
                )
                cvss_v2 = cvss_v2 or self._extract_mitre_metric(
                    metric, "cvssV2_0", adp_source
                )
                other = metric.get("other", {})
                content = other.get("content", {})
                if other.get("type") == "kev" and short_name == "CISA-ADP":
                    cisa_kev = {
                            "source": "CISA ADP",
                            "date_added": content.get("dateAdded"),
                        "reference": content.get("reference"),
                    }
                elif other.get("type") == "ssvc" and short_name == "CISA-ADP":
                    ssvc.append(content)

            affected = self._merge_records(
                {"affected_systems": affected},
                {"affected_systems": self._extract_mitre_affected(provider.get("affected", []))},
            )["affected_systems"]

        # References
        refs = []
        for ref in cna.get("references", []):
            if not ref.get("url"):
                continue
            refs.append({
                "url": _sanitize(ref["url"], 512),
                "source": _sanitize(ref.get("name", ""), 64),
                "sources": ["MITRE"],
                "tags": ref.get("tags", []),
            })
        for provider in adp:
            for ref in provider.get("references", []):
                if not ref.get("url"):
                    continue
                refs.append({
                    "url": _sanitize(ref["url"], 512),
                    "source": _sanitize(
                        provider.get("providerMetadata", {}).get("shortName", ""),
                        64,
                    ),
                    "sources": ["MITRE"],
                    "tags": ref.get("tags", []),
                })

        # CWE
        cwes = []
        for problem in cna.get("problemTypes", []):
            for desc in problem.get("descriptions", []):
                if desc.get("lang") == "en":
                    cwes.append(desc.get("description", ""))

        return {
            "id":               cve_id,
            "description":      _sanitize(description),
            "published":        published,
            "modified":         modified,
            "cvss_v4":          cvss_v4,
            "cvss_v3":          cvss_v3,
            "cvss_v2":          cvss_v2,
            "affected_systems": affected,
            "refs":             refs,
            "cwes":             cwes,
            "cisa_kev":         cisa_kev,
            "ssvc":             ssvc,
            "poc":              [],          # filled later
            "source":           "MITRE",
            "source_details": [
                {
                    "source": "MITRE/CNA",
                    "trust_level": "authoritative",
                    "untrusted": False,
                },
                *[
                    {
                        "source": provider.get("providerMetadata", {}).get("shortName", "MITRE ADP"),
                        "trust_level": (
                            "authoritative"
                            if provider.get("providerMetadata", {}).get("shortName") == "CISA-ADP"
                            else "secondary"
                        ),
                        "untrusted": False,
                    }
                    for provider in adp
                ],
            ],
            "sources_checked":  ["MITRE"],
            "source_warnings":  [],
            "fetched_at":       datetime.now(timezone.utc).isoformat(),
        }

    @classmethod
    def _extract_nvd_cvss(cls, metrics: dict, key: str) -> dict | None:
        metric_data = metrics.get(key) or []
        if not metric_data:
            return None
        metric = metric_data[0]
        cvss = metric.get("cvssData", {})
        return cls._normalize_cvss(
            cvss,
            metric.get("baseSeverity") or cvss.get("baseSeverity", "UNKNOWN"),
            metric.get("exploitabilityScore"),
            metric.get("impactScore"),
            source="NVD",
        )

    @classmethod
    def _extract_cvssv3(cls, metrics: dict) -> dict | None:
        return cls._extract_nvd_cvss(metrics, "cvssMetricV31") or cls._extract_nvd_cvss(
            metrics, "cvssMetricV30"
        )

    @classmethod
    def _extract_cvssv2(cls, metrics: dict) -> dict | None:
        return cls._extract_nvd_cvss(metrics, "cvssMetricV2")

    @classmethod
    def _extract_mitre_cvss(
        cls, metrics: list, key: str, source: str = "MITRE CNA"
    ) -> dict | None:
        for metric in metrics:
            parsed = cls._extract_mitre_metric(metric, key, source)
            if parsed:
                return parsed
        return None

    @classmethod
    def _extract_mitre_metric(
        cls, metric: dict, key: str, source: str = "MITRE ADP"
    ) -> dict | None:
        cvss = metric.get(key)
        if not isinstance(cvss, dict):
            return None
        return cls._normalize_cvss(
            cvss,
            cvss.get("baseSeverity", "UNKNOWN"),
            source=source,
        )

    @staticmethod
    def _normalize_cvss(
        cvss: dict,
        severity: str = "UNKNOWN",
        exploitability_score: float | None = None,
        impact_score: float | None = None,
        source: str = "",
    ) -> dict:
        return {
            "score": cvss.get("baseScore"),
            "severity": severity or "UNKNOWN",
            "vector": cvss.get("vectorString", ""),
            "exploitability_score": exploitability_score,
            "impact_score": impact_score,
            "attack_vector": cvss.get("attackVector"),
            "attack_complexity": cvss.get("attackComplexity"),
            "privileges_required": cvss.get("privilegesRequired"),
            "user_interaction": cvss.get("userInteraction"),
            "scope": cvss.get("scope"),
            "confidentiality_impact": cvss.get("confidentialityImpact"),
            "integrity_impact": cvss.get("integrityImpact"),
            "availability_impact": cvss.get("availabilityImpact"),
            "source": source,
            "trust_level": (
                "authoritative"
                if source in {"NVD", "MITRE CNA"} or source.startswith("CISA-ADP")
                else "secondary"
            ),
            "untrusted": False,
        }

    @staticmethod
    def _extract_mitre_affected(affected: list) -> list[dict]:
        systems = []
        for product in affected:
            vendor = product.get("vendor") or "Unknown"
            name = product.get("product") or "Unknown"
            versions = product.get("versions") or [
                {"version": "All versions", "status": product.get("defaultStatus", "unknown")}
            ]
            for version in versions:
                status = version.get("status", product.get("defaultStatus", "unknown"))
                if status not in {"affected", "unknown", "unaffected"}:
                    continue
                start = version.get("version", "")
                end = version.get("lessThan") or version.get("lessThanOrEqual", "")
                upper_operator = "<=" if version.get("lessThanOrEqual") else "<"
                if end:
                    version_range = (
                        f">= {start}, {upper_operator} {end}"
                        if start and start != "*"
                        else f"{upper_operator} {end}"
                    )
                else:
                    version_range = start or "All versions"
                systems.append(
                    {
                        "vendor": vendor,
                        "product": name,
                        "version": start or "All versions",
                        "version_start": start or None,
                        "version_end": end or None,
                        "version_range": version_range,
                        "version_type": version.get("versionType", ""),
                        "status": status,
                        "cpe": "",
                        "source": "MITRE",
                        "trust_level": "authoritative",
                        "untrusted": False,
                    }
                )
        return systems

    @staticmethod
    def _extract_osv_affected(affected: list) -> list[dict]:
        if not isinstance(affected, list):
            raise ValueError("OSV response has an invalid affected field.")
        systems = []
        for item in affected:
            if not isinstance(item, dict):
                continue
            package = item.get("package") or {}
            if not isinstance(package, dict):
                continue
            product = package.get("name")
            ecosystem = package.get("ecosystem")
            if not product or not ecosystem:
                continue

            ranges = item.get("ranges", [])
            if not isinstance(ranges, list):
                raise ValueError("OSV affected entry has an invalid ranges field.")
            for affected_range in ranges:
                if not isinstance(affected_range, dict):
                    continue
                range_type = affected_range.get("type", "")
                events = affected_range.get("events", [])
                if not isinstance(events, list):
                    raise ValueError("OSV affected range has an invalid events field.")
                introduced = None
                for event in events:
                    if not isinstance(event, dict):
                        continue
                    if "introduced" in event:
                        introduced = event["introduced"]
                        continue

                    end = event.get("fixed") or event.get("last_affected")
                    if not end:
                        continue
                    start = introduced
                    lower = f">= {start}" if start and start != "0" else ""
                    upper_operator = "<=" if "last_affected" in event else "<"
                    upper = f"{upper_operator} {end}"
                    version_range = ", ".join(part for part in (lower, upper) if part)
                    if range_type.upper() == "GIT":
                        version_range = f"commit {version_range}"
                    systems.append(
                        {
                            "vendor": ecosystem,
                            "product": product,
                            "version": start or "All versions",
                            "version_start": start or None,
                            "version_end": end,
                            "version_range": version_range,
                            "version_type": range_type,
                            "status": "affected",
                            "cpe": "",
                            "source": "OSV",
                            "trust_level": "secondary",
                            "untrusted": False,
                        }
                    )
                    introduced = None

                if introduced is not None:
                    lower = f">= {introduced}" if introduced != "0" else ""
                    version_range = lower or "All versions"
                    if range_type.upper() == "GIT":
                        version_range = f"commit {version_range}"
                    systems.append(
                        {
                            "vendor": ecosystem,
                            "product": product,
                            "version": introduced or "All versions",
                            "version_start": introduced or None,
                            "version_end": None,
                            "version_range": version_range,
                            "version_type": range_type,
                            "status": "affected",
                            "cpe": "",
                            "source": "OSV",
                            "trust_level": "secondary",
                            "untrusted": False,
                        }
                    )

            if not item.get("ranges"):
                for version in item.get("versions", []):
                    systems.append(
                        {
                            "vendor": ecosystem,
                            "product": product,
                            "version": version,
                            "version_start": version,
                            "version_end": version,
                            "version_range": version,
                            "version_type": "exact",
                            "status": "affected",
                            "cpe": "",
                            "source": "OSV",
                            "trust_level": "secondary",
                            "untrusted": False,
                        }
                    )
        return systems

    @staticmethod
    def _extract_cpe(configurations: list) -> list[dict]:
        systems, seen = [], set()

        def add_nodes(nodes: list) -> None:
            for node in nodes:
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", False):
                        continue
                    cpe = match.get("criteria", "")
                    parts = cpe.split(":")
                    if len(parts) < 6:
                        continue
                    vendor, product, version = parts[3], parts[4], parts[5]
                    key = (
                        cpe,
                        match.get("versionStartIncluding"),
                        match.get("versionStartExcluding"),
                        match.get("versionEndIncluding"),
                        match.get("versionEndExcluding"),
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    systems.append(
                        {
                            "vendor":        vendor.replace("_", " ").title(),
                            "product":       product.replace("_", " ").title(),
                            "version":       version if version != "*" else "All versions",
                            "version_start": match.get("versionStartIncluding")
                                             or match.get("versionStartExcluding"),
                            "version_end":   match.get("versionEndIncluding")
                                             or match.get("versionEndExcluding"),
                            "version_range": NVDClient._format_cpe_version_range(match),
                            "version_type": "CPE",
                            "status":        "affected",
                            "cpe":           cpe,
                            "source":        "NVD",
                            "trust_level":   "authoritative",
                            "untrusted":     False,
                        }
                    )
                add_nodes(node.get("nodes", []))

        for cfg in configurations:
            add_nodes(cfg.get("nodes", []))
        return systems

    @staticmethod
    def _format_cpe_version_range(match: dict) -> str:
        start = match.get("versionStartIncluding")
        start_exclusive = match.get("versionStartExcluding")
        end = match.get("versionEndIncluding")
        end_exclusive = match.get("versionEndExcluding")
        bounds = []
        if start:
            bounds.append(f">= {start}")
        elif start_exclusive:
            bounds.append(f"> {start_exclusive}")
        if end:
            bounds.append(f"<= {end}")
        elif end_exclusive:
            bounds.append(f"< {end_exclusive}")
        return ", ".join(bounds)

    # ------------------------------------------------------------------ #
    # PoC Aggregation                                                      #
    # ------------------------------------------------------------------ #
    def _collect_poc(self, cve_id: str) -> list[dict]:
        poc: list[dict] = []
        poc.extend(self._exploitdb_search(cve_id))
        poc.extend(self._github_poc_index(cve_id))
        return poc[:15]                   # cap total PoCs returned

    def _exploitdb_search(self, cve_id: str) -> list[dict]:
        """Query ExploitDB JSON search endpoint."""
        results = []
        # ExploitDB expects the numeric portion only
        num = re.sub(r"(?i)^CVE-", "", cve_id)
        try:
            resp = self.session.get(
                EXPLOITDB_API,
                params={"cve": num, "type": "", "platform": ""},
                headers={"X-Requested-With": "XMLHttpRequest", "Accept": "application/json"},
                timeout=8,
            )
            if resp.status_code == 200:
                for item in resp.json().get("data", [])[:6]:
                    eid = item.get("id", "")
                    results.append(
                        {
                            "title":    _sanitize(item.get("description", "No title"), 200),
                            "url":      f"https://www.exploit-db.com/exploits/{eid}",
                            "type":     _sanitize(
                                (item.get("type") or {}).get("name", "Unknown")
                                if isinstance(item.get("type"), dict)
                                else str(item.get("type", "Unknown")),
                                64,
                            ),
                            "platform": _sanitize(
                                (item.get("platform") or {}).get("name", "Unknown")
                                if isinstance(item.get("platform"), dict)
                                else str(item.get("platform", "Unknown")),
                                64,
                            ),
                            "author":   _sanitize(
                                (item.get("author") or {}).get("name", "Unknown")
                                if isinstance(item.get("author"), dict)
                                else str(item.get("author", "Unknown")),
                                64,
                            ),
                            "date":     item.get("date_published", ""),
                            "source":   "ExploitDB",
                            "trust_level": "unverified",
                            "untrusted": True,
                        }
                    )
        except Exception as exc:
            log.debug("ExploitDB query failed for %s: %s", cve_id, exc)
        return results

    def _github_poc_index(self, cve_id: str) -> list[dict]:
        """Check nomi-sec/PoC-in-GitHub raw JSON index."""
        results = []
        # Extract year from CVE-YYYY-NNNNN
        m = re.match(r"(?i)CVE-(\d{4})-\d+", cve_id)
        if not m:
            return results
        year = m.group(1)
        url  = POCGITHUB_RAW.format(year=year, cve_id=cve_id.upper())
        try:
            resp = self.session.get(url, timeout=6)
            if resp.status_code == 200:
                for entry in resp.json()[:8]:
                    results.append(
                        {
                            "title":       _sanitize(entry.get("name", "GitHub PoC"), 200),
                            "url":         _sanitize(entry.get("html_url", ""), 512),
                            "description": _sanitize(entry.get("description", ""), 300),
                            "stars":       entry.get("stargazers_count", 0),
                            "date":        entry.get("created_at", ""),
                            "source":      "GitHub",
                            "trust_level": "unverified",
                            "untrusted":   True,
                        }
                    )
        except Exception as exc:
            log.debug("PoC-in-GitHub lookup failed for %s: %s", cve_id, exc)
        return results
