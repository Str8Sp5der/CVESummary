## Requirements

- Python 3.10 or newer
- Windows PowerShell or Command Prompt
- Internet access for live CVE lookups and synchronization

## Install and Run

From the project directory, create an isolated environment, install the runtime dependencies, and start the server:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Open **http://127.0.0.1:5000** in a browser. The server listens on localhost only. Stop it with `Ctrl+C` in the terminal running it.

If `.venv` already exists but its Python executable is missing or points to a different machine, create a fresh environment in a different directory (for example, `.venv-local`) and use that environment's Python for the install and run commands.

To run the isolated automated tests, install the development dependencies and use pytest. These commands assume the `.venv` environment above; substitute `.venv-local` if you created that environment instead:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
```

The test suite uses temporary databases and mocked upstream requests; it does not need the running app or the local application database.

## Using the App

Search for a CVE ID (for example, `CVE-2021-44228`) to fetch it directly. Typing a description shows local suggestions; press **Enter** to search NVD's full published-CVE index and combine its latest matches with local results. CVE summaries can be viewed without signing in. Create an account and sign in to use the authenticated PoC references panel.

The local SQLite database is stored in `data/cve_database.db`. The app creates or initializes it on startup.

## How the Database Works

- `cves` stores one current row per CVE ID. Searchable columns such as ID, description, publication date, severity, and score are ordinary SQLite columns. The variable-length provider results (CVSS detail, affected systems, references, source checks, CISA assessments, and PoC links) are JSON encoded in that row. This keeps local reads and writes simple while the source set is still evolving; it is a cache of the latest merged record, not an immutable history of every provider response.
- `source_observations` retains provider records and retrieval outcomes, keyed by CVE, source, record ID, and content hash. Snapshots record retrieval time, source update time when provided, trust level, review status, and a compact summary of provider claims or retrieval status. Repeated identical records are deduplicated. CVE responses expose claim summaries and snapshot counts, not raw provider payloads. `source_syncs` records catalog sync outcomes; `/api/stats` reports these jobs and the number of retained snapshots.
- `source_details` represents the latest attempt per provider, including its outcome and attempt time; `last_successful_retrieval_at` and `last_successful_payload_at` separately track the last valid response and payload. A failed or partial attempt leaves the previous successful payload and its timestamp intact. `source_warnings` represents current unresolved provider warnings, while prior retrieval outcomes remain discoverable in `source_observations`. Identical payload snapshots are deduplicated and their `retrieved_at` is advanced to the latest retrieval. `sources_checked` remains a compatibility list of providers checked at least once and is not used to determine which providers an update replaced.
- `store_cve()` performs an upsert. Missing fields mean “not supplied”; an explicit empty list from a valid provider response may replace that provider's attributed claims. A confirmed no-record result removes only affected-system, reference, and KEV contributions attributed to that provider. Claims without reliable provider attribution are retained because they cannot safely be assigned or deleted. Failed and malformed responses preserve existing payload data; malformed affected-system or reference lists are treated as partial updates.
- `cves_fts` is an FTS5 external-content index over CVE IDs and descriptions. Database triggers keep it aligned with inserts and updates; it supports local description search. Normal CVE-ID prefix searches use the primary-key index.
- `users`, `failed_logins`, and `update_log` hold account data, login throttling history, and synchronization outcomes. SQL values are parameterized.
- SQLite uses WAL mode so readers can continue while a writer commits, with `synchronous=NORMAL`. Writes that read and merge an existing record are serialized with `BEGIN IMMEDIATE`, and connections wait briefly for a competing writer before returning a lock error.
- The schema initializes and adds missing columns at startup. The database is local runtime state and should not be shared by multiple machines over a network filesystem. Back up a live database using SQLite's backup API rather than copying only the `.db` file while WAL is active.

The JSON-in-row design is adequate for this single-instance local app, but it is not yet a strong foundation for high-volume API workloads or source-level history. If the project grows into a multi-worker service, move to a server database and consider separate CVE, affected-range, reference, source-observation, and user tables with explicit migrations.

## CVE Data Sources and Synchronization

- Live CVE fetches query NVD CVE API 2.0, the MITRE CVE Program record, OSV.dev, GitHub's Advisory Database, Red Hat's Security Data API, and CISA KEV. Requests have finite timeouts; explicit POST lookups are rate-limited to 40 requests per minute and 200 per hour. GET requests only read the local cache; uncached or stale records require an explicit POST lookup, and forced refresh remains authenticated. NVD scores take precedence when both provide the same CVSS version; CNA/ADP records, ecosystem package records, and vendor advisories supplement affected products, versions, CVSS metrics, and references. Each affected entry identifies its contributing source(s).
- The local catalog can be seeded from all NVD CVE API records with `sync_data.py --nvd-full`. The web app syncs NVD records modified in the previous seven days every six hours, providing an overlap window after brief outages, and mirrors the complete CISA KEV catalog on the same schedule. These catalog jobs preserve changed upstream snapshots and report their latest status in `/api/stats`. The full NVD seed is intentionally an explicit command because it is paginated, rate-limited, and can take time; it does not run during app startup.
- MITRE, OSV, GitHub Advisory, and Red Hat are queried for a requested CVE and cached locally; they are not currently full historical mirrors. The database therefore grows from the NVD seed, KEV catalog, and CVEs looked up or refreshed. A full third-party mirror is not implied by having an integration. Provider snapshots preserve source evidence for records the app has actually retrieved.
- The source-specific snapshot history lets the UI/API show which provider record was retrieved and when, while the merged response continues to show field-level source labels. Provider outages and “no matching record” remain distinct statuses. Changed upstream records are retained as new snapshots; direct KEV catalog refreshes also remove stale KEV inclusion from the current merged view.
- The UI shows provider CVSS assessments alongside the selected aggregate score. If another source reports a different score for the same CVSS version, the discrepancy is labeled rather than discarded; the aggregate still follows the existing provider-priority rules. Affected-system entries also retain source attribution, so distinct version ranges remain visible instead of being silently overwritten.
- Source labels distinguish the source of a claim from its review status: NVD and CVE Program records are labeled authoritative, OSV is secondary, and GitHub-reviewed advisories are labeled curated. GitHub advisories marked `unreviewed` are explicitly labeled unverified/untrusted on their affected-product, score, and reference data. “Reviewed” indicates GitHub's review status, not a guarantee of correctness; verify important findings against the CVE record and vendor advisories.
- When GitHub returns multiple advisories for a CVE, the app combines their package data and preserves each advisory's identity and review status. If multiple GitHub records provide a score of the same CVSS version, a reviewed score is preferred over an unreviewed score; NVD/MITRE and Red Hat metrics take precedence over GitHub scores.
- Red Hat's vendor API contributes Red Hat package states, fixed releases, CVSS metrics, references, and CWE data. Its `Affected`, `Fix deferred`, and `Will not fix` package states are presented as affected; `Not affected` stays explicitly unaffected. Draft Red Hat CVSS metrics are marked unverified, while verified metrics and vendor data are attributed to Red Hat. Red Hat states that this API is for information and metrics purposes; its published data is CC BY 4.0 and requires attribution.
- The official CISA KEV catalog is mirrored locally every six hours and is also cached in memory for live lookups, supplementing KEV details present in CVE Program records. When an entry is removed from the current catalog, CVESummary clears the current KEV flag while retaining the source-history event. SSVC assessments are shown when present in the CVE Program's CISA-ADP container. KEV identifies vulnerabilities known to be exploited; SSVC is a prioritization assessment, not a complete source of affected versions.
- Proof-of-concept references from ExploitDB and the GitHub PoC index are community-supplied, not validated by CVESummary, and are flagged **UNVERIFIED CODE**. Review them cautiously; the app does not download or execute them.
- The app parses CVSS v4.0, v3.x, and v2 when published, retains CPE and CNA product/version ranges without truncating the affected-product list, and displays CISA Known Exploited Vulnerabilities (KEV) and SSVC assessments when included in the CVE record.
- No source provides complete scoring or affected-version information for every CVE. If upstream records omit a field, it remains unavailable rather than being inferred. Cached records with missing enrichment or retained data from failed, partial, or no-record provider outcomes are served as stale; use the CVE detail page to request a POST lookup or signed-in forced refresh.
- Search results cover published CVEs indexed by NVD; reserved, rejected, unpublished, or newly assigned IDs may not appear in NVD search. If every CVE source is unreachable or rate-limits the request, the API reports an upstream-unavailable error rather than claiming the CVE does not exist. Partial source failures are included as coverage warnings.
- `GET /api/search` searches only cached records. `GET /api/search/live` adds an NVD keyword search and is limited to two requests per minute to stay within NVD's unauthenticated request allowance.
- `GET /api/cve/<id>` reads the cache only; `POST /api/cve/<id>` performs a live lookup. Unsafe browser requests require the session CSRF token. A stale response retains prior data and identifies it as stale; an uncached lookup with no usable record returns 503 with per-provider outcomes, distinguishing confirmed no-record results from upstream failures. This GET-to-POST change is breaking for clients that relied on GET to trigger retrieval.
- `POST /api/cve/<id>/refresh` forces a live refresh for a signed-in user. `GET` is rejected; the browser sends a CSRF token.
- A background job syncs records modified during the previous seven days every six hours. It pages through the NVD results and updates existing CVE records.
- CISA KEV catalog ingestion runs every six hours. To run either sync manually without starting the web server:

```powershell
.\.venv\Scripts\python.exe sync_data.py --nvd-full
.\.venv\Scripts\python.exe sync_data.py --nvd-recent --days-back 3
.\.venv\Scripts\python.exe sync_data.py --cisa-kev
```

The full NVD seed uses the official paginated API. NVD's unauthenticated rate limit can make a first seed slow; configure `NVD_API_KEY` before running it to raise the request allowance. Rerun a failed seed from the beginning; existing rows are upserted and unchanged source snapshots are deduplicated.
- Bulk sync does not query PoC sources.
- Manual feed synchronization is currently disabled for all web users. Scheduled NVD and CISA KEV synchronization continues; re-enabling a manual endpoint requires administrator authorization backed by secure provisioning. Registration alone must never grant that permission.
- An NVD API key is optional. Set `NVD_API_KEY` before starting the app to use NVD's higher request limit:

```powershell
$env:NVD_API_KEY="your-api-key-here"
.\.venv\Scripts\python.exe app.py
```

Apply for a key at https://nvd.nist.gov/developers/request-an-api-key.

- A GitHub token is optional. Set `GITHUB_TOKEN` to authenticate GitHub Advisory Database requests and raise the API rate limit. Keep the token private; do not commit it to the repository.

```powershell
$env:GITHUB_TOKEN="your-github-token-here"
.\.venv\Scripts\python.exe app.py
```

## Source References

- [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) — NIST's CVE records, CPE configurations, and CVSS analysis.
- [CVE Services API](https://cveawg.mitre.org/api-docs/) — CVE Program records published by CNAs and ADPs, including affected-product and CISA-ADP data.
- [OSV API](https://google.github.io/osv.dev/api/) — open-source ecosystem vulnerability records and package/version ranges.
- [GitHub global security advisories API](https://docs.github.com/en/rest/security-advisories/global-advisories) — package advisories; the app preserves GitHub's reviewed/unreviewed status.
- [Red Hat Security Data API CVE endpoint](https://docs.redhat.com/en/documentation/red_hat_security_data_api/1.0/security_data_api-cve) and [Red Hat Security Data terms](https://access.redhat.com/security/data) — Red Hat-specific product, package-state, and fixed-release details. Red Hat API data requires CC BY 4.0 attribution.
- [CISA Known Exploited Vulnerabilities catalog and feed](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [CISA SSVC guidance](https://www.cisa.gov/resources-tools/resources/stakeholder-specific-vulnerability-categorization-ssvc) — direct exploitation status and prioritization information.

These sources are complementary, not exhaustive: no single public source provides verified CVSS scores and complete affected-version ranges for every CVE. Vendor APIs and advisories are authoritative only for their own products, so missing Red Hat data does not mean a CVE is not affected in other ecosystems. Results retain source attribution and do not infer missing scores or version ranges.

## Running Tests

The focused client and database tests use mocked responses and do not require a running server or network access:

```powershell
.\.venv\Scripts\python.exe -m unittest test_nvd_client test_database
```

## Updating Dependencies

`requirements.txt` lists the app's runtime dependencies with minimum supported versions. To upgrade them in the virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade -r requirements.txt
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError` for a project dependency | Activate the intended virtual environment and run `python -m pip install -r requirements.txt`. |
| The virtualenv Python refers to a different machine or cannot start | Create a fresh environment in another directory, install the requirements there, and run `app.py` with that Python. |
| Port 5000 is already in use | Stop the other process using port 5000, then restart the app. |
| Browser cannot connect | Confirm the terminal reports `Running on http://127.0.0.1:5000` and that the server process is still running. |
