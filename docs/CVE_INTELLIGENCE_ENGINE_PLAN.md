# CVESummary: Vulnerability Intelligence Engine Plan

## Product objective

Turn CVESummary into a source-agnostic vulnerability intelligence engine that can later serve the larger project through a stable API. The current Flask UI is a client of the engine, not the owner of provider logic. A CVE lookup should gather every relevant, accessible source and return a normalized record with field-level provenance, freshness, confidence/review metadata, and explicit retrieval outcomes.

The coverage target is **all verifiable data available from integrated upstream sources**, not a fabricated guarantee that every CVE has every field. Some records have no published CVSS assessment, precise affected-version range, or public PoC. Those cases must be reported as unavailable/absent rather than inferred.

## Primary output contract

For each CVE, the normalized record must support:

1. **Description** — preferred human-readable description plus all distinct provider observations and language/source metadata.
2. **Affected systems** — vendor, product, package ecosystem, package URL (purl), CPE, platform/release, affected status, version scheme, inclusive/exclusive bounds, exact versions, fixed versions, and vendor disposition (affected, unaffected, fixed, deferred, will-not-fix, unknown). Preserve multiple overlapping claims and their source attribution.
3. **CVSS** — retain every provider assessment independently: CVSS version, base score, severity, vector, source/CNA, assessment type, trust/review state, and publication/update time. Never collapse competing scores into one silently. A selected display score is a derived convenience, not the canonical data.
4. **PoCs and exploit references** — separate proof-of-concept code, exploit-db entries, vendor patches, advisory references, and generic references. Record repository/advisory URL, source, observed date, code/reference type, and verification status. Never imply that an indexed PoC is safe, functional, or validated.
5. **Exploit/prioritization signals** — keep CISA KEV (known exploitation), FIRST EPSS (probability estimate), and SSVC (prioritization assessment) as separate signal types. EPSS is not CVSS; KEV is not a PoC.
6. **Provenance and retrieval state** — each provider attempt records status, attempt time, last successful retrieval, last successful payload, source update time, record ID, trust/review metadata, and field claims.

## Target architecture

`providers/` (or equivalent modules) contains one adapter per upstream source. An adapter has a small, consistent contract: fetch one CVE or a batch; validate the response; return normalized claims plus the original/compact source observation; classify the outcome as successful, confirmed no-record, partial/malformed, or unavailable. It must not write directly to the database or know about Flask.

A provider registry describes provider name, scope, authority, supported fields, retrieval mode (single-record, query, or bulk feed), update cadence, licensing/attribution, and whether its output is product/vendor-specific. The orchestrator invokes relevant providers independently (bounded concurrency, per-provider timeouts/retries/backoff), collects partial successes, and passes them to a deterministic merge layer.

The merge layer is field-aware and non-destructive:
- a missing value never overwrites an existing value;
- only a successful, validated provider response can replace that provider's prior claims;
- a confirmed no-record response removes only claims attributed to that provider, never other providers' claims;
- unavailable/partial responses preserve prior payload and expose the failed attempt;
- conflicting scores, version ranges, and product identities remain separately visible;
- normalization never destroys the original source observation;
- source priority is field-specific, not a single global provider ranking.

The persistence layer stores canonical CVE identity, normalized entities/claims, source observations and immutable payload snapshots, provider attempt state, feed checkpoints, and synchronization history. SQLite remains acceptable for the local prototype, but repository/service boundaries must not depend on SQLite-specific query behavior. Before multi-worker/API deployment, migrate to PostgreSQL with explicit schema migrations and indexes.

The service layer exposes stable operations such as `get_vulnerability(cve_id, refresh_policy)`, `refresh_vulnerability(cve_id)`, `search_vulnerabilities(query, filters)`, and `get_source_status(cve_id)`. Flask routes and the future API both call this layer. API transport, authentication, pagination, quotas, and versioning remain separate concerns.

## Source coverage and integration order

### Already present — audit, harden, and keep
- NVD CVE API 2.0: CVSS, CPE applicability, references, NVD catalog.
- CVE Program CVE Services and CVEProject cvelistV5: CNA/ADP descriptions, affected products/ranges, references, CVSS/SSVC when supplied. Treat these as two delivery paths for one source family, not independent authorities.
- OSV: ecosystem aliases, package affected ranges, fixed versions, package identifiers.
- GitHub Global Security Advisories: reviewed/unreviewed advisory data, package ranges, patches, CVSS, references.
- Red Hat Security Data: Red Hat-specific package states, releases, CVSS and references.
- CISA KEV: known-exploited catalog and metadata.
- Existing ExploitDB and nomi-sec PoC-in-GitHub lookups: maintain distinct PoC/reference classes and unverified labels.

### Next integrations
1. FIRST EPSS: per-CVE lookup for live enrichment and daily CSV feed for catalog synchronization. Persist score, percentile, score date/model metadata, source attribution, and historical observations. FIRST explicitly recommends the API for one/small batches and CSV for bulk synchronization.
2. Debian Security Tracker: vendor/package status and fixed-version enrichment, preferably from its structured tracker data.
3. Ubuntu Security Notices / Ubuntu OVAL: Ubuntu-specific package status and fixed versions. Prefer the structured OVAL feed for bulk ingestion; treat the Ubuntu Security API as unstable until its production status changes.
4. Broaden PoC coverage: identify and integrate additional reputable exploit/PoC indexes only after documenting API/feed stability, licensing, attribution, and false-positive characteristics. GitHub code search is not itself proof that a repository is a working exploit.
5. Add vendor-specific CSAF/VEX/advisory feeds selectively (e.g. vendors with substantial coverage and stable machine-readable feeds). Do not add generic feeds merely to inflate the provider count.

## Retrieval and synchronization strategy

Use a hybrid model:
- **On-demand**: per-CVE endpoints for immediate enrichment and provider APIs designed for individual lookup.
- **Bulk**: daily/periodic catalogs for high-value feeds (NVD, KEV, EPSS, Debian/Ubuntu structured data where available). Use conditional requests (ETag/Last-Modified), incremental checkpoints, bounded page sizes, and resumable jobs.
- **Refresh policy**: do not re-fetch every provider on every page view. Support explicit refresh, cache TTL by source volatility, stale-while-revalidate, and retry schedules for unavailable/partial providers.
- **Concurrency**: independent provider tasks with strict per-source timeouts, bounded parallelism, circuit breaking/backoff, and a total lookup deadline. One slow source must not block already-collected valid data.
- **Bulk safety**: validate feed shape and completeness before replacing a known-good snapshot; record feed version/checksum and only advance checkpoints after a committed batch.

## Canonical data and API readiness

Keep provider adapters and normalized domain models independent of Flask and SQLite. Add stable identifiers for source claims and affected entities. Use explicit schema migrations, typed validation, UTC timestamps, deterministic serialization, and documented null/absence semantics. Preserve backward-compatible UI fields as derived fields while introducing canonical arrays such as `cvss_assessments`, `affected`, `references`, `exploits`, and `signals`.

Future API requirements:
- versioned endpoints and OpenAPI schema;
- API keys/service authentication, scopes, quotas, and per-client rate limits;
- pagination and filtering for search and large affected/reference collections;
- idempotent refresh jobs with job/status resources rather than long-running request handlers;
- consistent error envelope distinguishing invalid ID, confirmed not found, partial response, upstream unavailable, and internal error;
- request IDs, structured logs, metrics, tracing, provider latency/error dashboards;
- no provider secrets in responses or logs;
- PostgreSQL and a job queue/worker for multi-instance deployment; Redis or equivalent for distributed rate limits/cache/locks.

## Testing and acceptance criteria

- Fixture-based parser tests for each provider, including malformed, empty, 404, rate-limited, timeout, and partial payloads.
- Merge tests proving empty/missing fields do not erase other-source claims and confirmed no-record removes only that provider's claims.
- Golden CVE fixtures spanning recent, historical, reserved/rejected, ecosystem-only, vendor-specific, multi-score, and PoC-rich records.
- Contract tests for the service layer and API response schema.
- Feed tests for truncated/empty/malformed downloads, checkpoint resume, idempotency, and unchanged ETags.
- Coverage report by field and provider; do not use raw provider count as a proxy for completeness.
- No integration is complete until its parser, provenance, persistence, refresh semantics, failure behavior, and documentation are tested.

## Phased execution roadmap

### Phase 0 — Baseline and architectural contract
- Preserve current working branch and the focused cvelistV5 fallback correction.
- Document the target domain model, source registry, outcome semantics, and migration path.
- Inventory all current parsers, storage fields, merge rules, scheduled jobs, and test fixtures.
- Identify data loss/coverage bugs before adding providers.

### Phase 1 — Core enrichment and data correctness
- Add FIRST EPSS as an independent signal, including persistence and source observations.
- Make provider outcomes/data collection registry-driven rather than hard-coded in route handlers.
- Ensure PoC retrieval is an independent enrichment path and failures do not invalidate CVE metadata.
- Preserve all CVSS assessments and affected claims with source-level attribution.
- Add regression fixtures and end-to-end mocked tests.

### Phase 2 — Vendor/package coverage
- Add Debian Security Tracker and Ubuntu OVAL/USN adapters.
- Normalize purl, CPE, ecosystem, distro release, version scheme, fixed versions, and vendor status without conflating them.
- Add source-specific synchronization and freshness tracking.

### Phase 3 — Provider orchestration and feed ingestion
- Introduce provider registry/adapter contract, bounded concurrent on-demand lookups, retries/backoff, and total deadlines.
- Add safe incremental bulk ingestion for EPSS and supported distro feeds; retain existing NVD/KEV sync semantics.
- Add field coverage and source health reporting.

### Phase 4 — Service/API boundary
- Extract framework-independent service and domain modules; make Flask a thin adapter.
- Define canonical response schema and OpenAPI contract; preserve current UI response as a compatibility projection.
- Add PostgreSQL migration plan and background job interface before multi-worker deployment.

### Phase 5 — Scale and quality
- Add further vendor/CSAF sources based on measured gaps.
- Build representative golden-CVE evaluation set and automated field coverage reports.
- Add operational metrics, provider health, rate-limit management, and API security controls.

## Execution guardrails

- Do not merge without explicit approval.
- Do not claim tests passed unless they were run.
- Do not label a provider integration as a mirror unless the data is actually bulk-ingested.
- Do not claim universal completeness; report source and field coverage honestly.
- Keep this work focused on vulnerability data completeness and the future service/API boundary. Avoid unrelated UI redesign or speculative product features.
