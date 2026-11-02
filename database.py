"""
database.py — CVE Intel local SQLite store
All queries use parameterized statements. No string interpolation in SQL.
"""

import sqlite3
import json
import hashlib
import logging
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

DB_PATH = Path("data/cve_database.db")
log = logging.getLogger(__name__)


class CVEDatabase:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # ------------------------------------------------------------------ #
    # Connection                                                           #
    # ------------------------------------------------------------------ #
    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._conn()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # Schema                                                               #
    # ------------------------------------------------------------------ #
    def _init_schema(self):
        conn = self._conn()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS cves (
                    id               TEXT PRIMARY KEY,
                    description      TEXT NOT NULL DEFAULT '',
                    published        TEXT,
                    modified         TEXT,
                    cvss_v4          TEXT,
                    cvss_v3          TEXT,
                    cvss_v2          TEXT,
                    affected_systems TEXT,
                    refs             TEXT,
                    cwes             TEXT,
                    cisa_kev         TEXT,
                    ssvc             TEXT,
                    sources_checked  TEXT NOT NULL DEFAULT '[]',
                    source_details   TEXT NOT NULL DEFAULT '[]',
                    source_warnings  TEXT NOT NULL DEFAULT '[]',
                    poc              TEXT,
                    severity         TEXT DEFAULT 'UNKNOWN',
                    cvss_score       REAL DEFAULT 0.0,
                    source           TEXT DEFAULT 'NVD',
                    fetched_at       TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_published  ON cves(published  DESC);
                CREATE INDEX IF NOT EXISTS idx_severity   ON cves(severity);
                CREATE INDEX IF NOT EXISTS idx_cvss_score ON cves(cvss_score DESC);
                CREATE INDEX IF NOT EXISTS idx_fetched    ON cves(fetched_at DESC);

                CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
                    id,
                    description,
                    content=cves,
                    content_rowid=rowid
                );

                CREATE TRIGGER IF NOT EXISTS cves_ai AFTER INSERT ON cves BEGIN
                    INSERT INTO cves_fts(rowid, id, description)
                    VALUES (new.rowid, new.id, new.description);
                END;

                CREATE TRIGGER IF NOT EXISTS cves_au AFTER UPDATE ON cves BEGIN
                    INSERT INTO cves_fts(cves_fts, rowid, id, description)
                    VALUES ('delete', old.rowid, old.id, old.description);
                    INSERT INTO cves_fts(rowid, id, description)
                    VALUES (new.rowid, new.id, new.description);
                END;

                CREATE TABLE IF NOT EXISTS update_log (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp    TEXT,
                    cves_updated INTEGER,
                    success      INTEGER
                );

                CREATE TABLE IF NOT EXISTS source_observations (
                    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id             TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
                    source             TEXT NOT NULL,
                    source_record_id   TEXT NOT NULL,
                    source_updated_at  TEXT,
                    retrieved_at       TEXT NOT NULL,
                    trust_level        TEXT NOT NULL DEFAULT 'unknown',
                    review_status      TEXT,
                    claims_json        TEXT NOT NULL DEFAULT '{}',
                    payload_sha256     TEXT NOT NULL,
                    payload_json       TEXT NOT NULL,
                    UNIQUE(cve_id, source, source_record_id, payload_sha256)
                );

                CREATE INDEX IF NOT EXISTS idx_source_observations_cve
                    ON source_observations(cve_id, source, id DESC);

                CREATE TABLE IF NOT EXISTS source_syncs (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    source           TEXT NOT NULL,
                    started_at       TEXT NOT NULL,
                    completed_at     TEXT NOT NULL,
                    success          INTEGER NOT NULL,
                    records_processed INTEGER NOT NULL DEFAULT 0,
                    error            TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_source_syncs_source
                    ON source_syncs(source, id DESC);

                CREATE TABLE IF NOT EXISTS users (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    username     TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at   TEXT,
                    last_login   TEXT
                );

                CREATE TABLE IF NOT EXISTS failed_logins (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    username  TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    ip_address TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_username ON users(username);
                CREATE INDEX IF NOT EXISTS idx_failed_logins ON failed_logins(username, timestamp);
            """)
            columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(cves)")
            }
            for column in (
                "cvss_v4",
                "cisa_kev",
                "ssvc",
                "sources_checked",
                "source_details",
                "source_warnings",
            ):
                if column not in columns:
                    conn.execute(f"ALTER TABLE cves ADD COLUMN {column} TEXT")
            observation_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(source_observations)")
            }
            if "claims_json" not in observation_columns:
                conn.execute(
                    "ALTER TABLE source_observations "
                    "ADD COLUMN claims_json TEXT NOT NULL DEFAULT '{}'"
                )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # Write                                                                #
    # ------------------------------------------------------------------ #
    def store_cve(self, data: dict):
        """Upsert a CVE record. All values parameterized."""
        severity = "UNKNOWN"
        score = 0.0
        if data.get("cvss_v4"):
            severity = data["cvss_v4"].get("severity", "UNKNOWN")
            score = float(data["cvss_v4"].get("score", 0))
        elif data.get("cvss_v3"):
            severity = data["cvss_v3"].get("severity", "UNKNOWN")
            score = float(data["cvss_v3"].get("score", 0))
        elif data.get("cvss_v2"):
            severity = data["cvss_v2"].get("severity", "UNKNOWN")
            score = float(data["cvss_v2"].get("score", 0))

        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT affected_systems, refs, cwes, cisa_kev, source "
                "FROM cves WHERE id = ?",
                (data["id"],),
            ).fetchone()
            old_affected = json.loads(existing["affected_systems"] or "[]") if existing else []
            old_refs = json.loads(existing["refs"] or "[]") if existing else []
            old_cwes = json.loads(existing["cwes"] or "[]") if existing else []
            checked_sources = data.get("sources_checked") or data.get(
                "source", ""
            ).split(" + ")
            unavailable_sources = {
                detail.get("source")
                for detail in data.get("source_details", [])
                if isinstance(detail, dict)
                and detail.get("status") == "unavailable"
            }
            refreshed_sources = [
                source
                for source in checked_sources
                if source not in unavailable_sources
            ]
            affected_systems = self._merge_affected_systems(
                old_affected,
                data.get("affected_systems", []),
                refreshed_sources,
                existing["source"] if existing else "",
            )
            refs = self._merge_refs(
                old_refs,
                data.get("refs") or [],
                refreshed_sources,
            )
            cwes = self._merge_unique(
                old_cwes + (data.get("cwes") or []), lambda item: item
            )
            cisa_kev = data.get("cisa_kev")
            if (
                cisa_kev is None
                and "CISA KEV" not in refreshed_sources
                and existing
            ):
                cisa_kev_json = existing["cisa_kev"] or "null"
            else:
                cisa_kev_json = json.dumps(cisa_kev)
            conn.execute(
                """
                INSERT INTO cves
                    (id, description, published, modified, cvss_v4, cvss_v3,
                     cvss_v2, affected_systems, refs, cwes, cisa_kev, ssvc,
                     sources_checked, source_details, source_warnings, poc,
                     severity, cvss_score, source, fetched_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    description      = CASE
                                           WHEN excluded.description IN ('', 'No description available.')
                                             THEN cves.description
                                           WHEN excluded.source = 'CISA KEV'
                                                AND cves.description != ''
                                             THEN cves.description
                                           ELSE excluded.description
                                       END,
                    published        = COALESCE(NULLIF(excluded.published, ''), cves.published),
                    modified         = COALESCE(NULLIF(excluded.modified, ''), cves.modified),
                    cvss_v4          = CASE WHEN excluded.cvss_v4 = 'null'
                                             THEN cves.cvss_v4 ELSE excluded.cvss_v4 END,
                    cvss_v3          = CASE WHEN excluded.cvss_v3 = 'null'
                                             THEN cves.cvss_v3 ELSE excluded.cvss_v3 END,
                    cvss_v2          = CASE WHEN excluded.cvss_v2 = 'null'
                                             THEN cves.cvss_v2 ELSE excluded.cvss_v2 END,
                    affected_systems = excluded.affected_systems,
                    refs             = excluded.refs,
                    cwes             = CASE WHEN excluded.cwes = '[]'
                                             THEN cves.cwes ELSE excluded.cwes END,
                    cisa_kev         = excluded.cisa_kev,
                    ssvc             = CASE WHEN excluded.ssvc = '[]'
                                             THEN cves.ssvc ELSE excluded.ssvc END,
                    sources_checked  = excluded.sources_checked,
                    source_details   = excluded.source_details,
                    source_warnings  = excluded.source_warnings,
                    poc              = CASE
                                           WHEN excluded.poc = '[]' THEN cves.poc
                                           ELSE excluded.poc
                                       END,
                    severity         = CASE WHEN excluded.cvss_v4 = 'null'
                                               AND excluded.cvss_v3 = 'null'
                                               AND excluded.cvss_v2 = 'null'
                                             THEN cves.severity ELSE excluded.severity END,
                    cvss_score       = CASE WHEN excluded.cvss_v4 = 'null'
                                               AND excluded.cvss_v3 = 'null'
                                               AND excluded.cvss_v2 = 'null'
                                             THEN cves.cvss_score ELSE excluded.cvss_score END,
                    source           = excluded.source,
                    fetched_at       = excluded.fetched_at
                """,
                (
                    data["id"],
                    data.get("description", ""),
                    data.get("published", ""),
                    data.get("modified", ""),
                    json.dumps(data.get("cvss_v4")),
                    json.dumps(data.get("cvss_v3")),
                    json.dumps(data.get("cvss_v2")),
                    json.dumps(affected_systems),
                    json.dumps(refs),
                    json.dumps(cwes),
                    cisa_kev_json,
                    json.dumps(data.get("ssvc", [])),
                    json.dumps(data.get("sources_checked", [])),
                    json.dumps(data.get("source_details", [])),
                    json.dumps(data.get("source_warnings", [])),
                    json.dumps(data.get("poc", [])),
                    severity,
                    score,
                    data.get("source", "NVD"),
                    data.get("fetched_at", datetime.now(timezone.utc).isoformat()),
                ),
            )
            for observation in data.get("source_records", []):
                if not isinstance(observation, dict):
                    raise ValueError("Source observations must be objects.")
                source = observation.get("source")
                record_id = observation.get("record_id")
                payload = observation.get("payload")
                if not isinstance(source, str) or not source:
                    raise ValueError("Source observations require a source name.")
                if not isinstance(record_id, str) or not record_id:
                    raise ValueError("Source observations require a record ID.")
                if not isinstance(payload, (dict, list)):
                    raise ValueError("Source observation payloads must be JSON objects or lists.")
                payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
                payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
                conn.execute(
                    """
                    INSERT INTO source_observations
                        (cve_id, source, source_record_id, source_updated_at,
                         retrieved_at, trust_level, review_status, claims_json,
                         payload_sha256, payload_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id, source, source_record_id, payload_sha256)
                    DO UPDATE SET claims_json = excluded.claims_json
                    """,
                    (
                        data["id"],
                        source,
                        record_id,
                        observation.get("source_updated_at") or None,
                        observation.get("retrieved_at")
                        or data.get("fetched_at")
                        or datetime.now(timezone.utc).isoformat(),
                        observation.get("trust_level") or "unknown",
                        observation.get("review_status") or None,
                        json.dumps(
                            observation.get("claims") or {},
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        payload_sha256,
                        payload_json,
                    ),
                )

    @staticmethod
    def _merge_unique(values: list, key_func) -> list:
        merged = []
        seen = set()
        for value in values:
            key = key_func(value)
            if key not in seen:
                seen.add(key)
                merged.append(value)
        return merged

    @staticmethod
    def _merge_refs(existing: list, incoming: list, refreshed_sources: list) -> list:
        refreshed = set(refreshed_sources)

        def was_refreshed(source: str) -> bool:
            return any(
                source == provider
                or source.startswith(f"{provider} (")
                for provider in refreshed
            )

        retained = []
        for ref in existing if isinstance(existing, list) else []:
            if not isinstance(ref, dict):
                retained.append(ref)
                continue
            sources = ref.get("sources")
            if not isinstance(sources, list) or not sources:
                retained.append(ref)
                continue
            remaining_sources = [
                source for source in sources if not was_refreshed(source)
            ]
            if not remaining_sources:
                continue
            if len(remaining_sources) != len(sources):
                ref = dict(ref)
                ref["sources"] = remaining_sources
            retained.append(ref)

        merged = []
        by_url = {}
        for ref in retained + (incoming if isinstance(incoming, list) else []):
            if not isinstance(ref, dict):
                if ref not in merged:
                    merged.append(ref)
                continue
            url = ref.get("url")
            if not url or url not in by_url:
                copied = dict(ref)
                merged.append(copied)
                if url:
                    by_url[url] = copied
                continue

            existing_ref = by_url[url]
            sources = []
            for entry in (existing_ref, ref):
                entry_sources = entry.get("sources") or []
                if not isinstance(entry_sources, list):
                    entry_sources = [entry_sources]
                for source in entry_sources:
                    if source and source not in sources:
                        sources.append(source)
            if sources:
                existing_ref["sources"] = sources
            if ref.get("untrusted"):
                existing_ref["untrusted"] = True
                existing_ref["trust_level"] = "unverified"
            elif "untrusted" in ref and "untrusted" not in existing_ref:
                existing_ref["untrusted"] = False
            if not existing_ref.get("source") and ref.get("source"):
                existing_ref["source"] = ref["source"]
        return merged

    @staticmethod
    def _merge_affected_systems(
        existing: list, incoming: list, source: str | list, existing_source: str = ""
    ) -> list[dict]:
        refreshed_sources = (
            set(source)
            if isinstance(source, list)
            else set((source or "").split(" + "))
        )
        previous_sources = set((existing_source or "").split(" + "))

        def was_refreshed(provider: str) -> bool:
            return any(
                provider == source
                or provider.startswith(f"{source} (")
                for source in refreshed_sources
            )

        existing = existing if isinstance(existing, list) else []
        incoming = incoming if isinstance(incoming, list) else []
        retained = []
        for system in existing:
            if not isinstance(system, dict):
                continue
            raw_sources = system.get("sources") or system.get("source")
            if not raw_sources:
                if refreshed_sources & previous_sources:
                    continue
                retained.append(system)
                continue
            sources = raw_sources if isinstance(raw_sources, list) else raw_sources.split(" + ")
            if not isinstance(sources, list):
                sources = [sources]
            remaining_sources = [
                item for item in sources if not was_refreshed(item)
            ]
            if sources and not remaining_sources:
                continue
            if sources and len(remaining_sources) != len(sources):
                system = dict(system)
                system["source"] = " + ".join(remaining_sources)
                if len(remaining_sources) > 1:
                    system["sources"] = remaining_sources
                else:
                    system.pop("sources", None)
            retained.append(system)

        key_fields = (
            "cpe",
            "vendor",
            "product",
            "version",
            "version_range",
            "patched_version",
            "status",
        )
        systems = []
        by_key = {}
        for system in retained + incoming:
            if not isinstance(system, dict):
                continue
            key = tuple(system.get(field) for field in key_fields)
            existing_system = by_key.get(key)
            if existing_system is None:
                copied = dict(system)
                by_key[key] = copied
                systems.append(copied)
                continue

            sources = []
            for entry in (existing_system, system):
                source_list = entry.get("sources") or (entry.get("source") or "").split(" + ")
                if not isinstance(source_list, list):
                    source_list = [source_list]
                for item in source_list:
                    if item and item not in sources:
                        sources.append(item)
            if sources:
                existing_system["source"] = " + ".join(sources)
                if len(sources) > 1:
                    existing_system["sources"] = sources
                else:
                    existing_system.pop("sources", None)
            existing_system["untrusted"] = bool(
                existing_system.get("untrusted") or system.get("untrusted")
            )
            if existing_system["untrusted"]:
                existing_system["trust_level"] = "unverified"
        return systems

    def log_update(self, count: int, success: bool):
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO update_log (timestamp, cves_updated, success) VALUES (?,?,?)",
                (datetime.now(timezone.utc).isoformat(), count, 1 if success else 0),
            )

    def log_source_sync(
        self,
        source: str,
        started_at: str,
        success: bool,
        records_processed: int,
        error: str | None = None,
    ) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO source_syncs
                    (source, started_at, completed_at, success, records_processed, error)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    source,
                    started_at,
                    datetime.now(timezone.utc).isoformat(),
                    int(success),
                    records_processed,
                    error,
                ),
            )

    # ------------------------------------------------------------------ #
    # Read                                                                 #
    # ------------------------------------------------------------------ #
    def get_cve(self, cve_id: str) -> dict | None:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM cves WHERE id = ?", (cve_id,)
            ).fetchone()
            if not row:
                return None
            observations = conn.execute(
                """
                SELECT latest.source, latest.source_record_id,
                       latest.source_updated_at, latest.retrieved_at,
                       latest.trust_level, latest.review_status,
                       latest.claims_json AS claims,
                       versions.snapshot_count
                FROM source_observations AS latest
                JOIN (
                    SELECT source, source_record_id, MAX(id) AS latest_id,
                           COUNT(*) AS snapshot_count
                    FROM source_observations
                    WHERE cve_id = ?
                    GROUP BY source, source_record_id
                ) AS versions ON latest.id = versions.latest_id
                ORDER BY latest.source, latest.source_record_id
                """,
                (cve_id,),
            ).fetchall()
        result = self._full(row)
        result["source_observations"] = [
            self._parse_json_fields(dict(item), ["claims"]) for item in observations
        ]
        return result

    def search_cves(self, query: str, limit: int = 25) -> list[dict]:
        with self._connection() as conn:
            # Direct CVE-ID prefix search
            if query.upper().startswith("CVE-"):
                rows = conn.execute(
                    "SELECT * FROM cves WHERE id LIKE ? ORDER BY published DESC LIMIT ?",
                    (f"{query.upper()}%", limit),
                ).fetchall()
            else:
                # Full-text search on description + id
                try:
                    rows = conn.execute(
                        """
                        SELECT c.* FROM cves c
                        JOIN cves_fts f ON c.rowid = f.rowid
                        WHERE cves_fts MATCH ?
                        ORDER BY rank
                        LIMIT ?
                        """,
                        (query, limit),
                    ).fetchall()
                except sqlite3.OperationalError as exc:
                    log.warning(
                        "Full-text search failed for %r; using description search: %s",
                        query,
                        exc,
                    )
                    rows = conn.execute(
                        "SELECT * FROM cves WHERE description LIKE ? LIMIT ?",
                        (f"%{query}%", limit),
                    ).fetchall()
        return [self._summary(r) for r in rows]

    def get_recent_cves(self, limit: int = 30) -> list[dict]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM cves ORDER BY published DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._summary(r) for r in rows]

    def get_cve_ids_with_kev(self) -> list[str]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT id FROM cves WHERE cisa_kev IS NOT NULL AND cisa_kev != 'null'"
            ).fetchall()
        return [row["id"] for row in rows]

    def get_stats(self) -> dict:
        with self._connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) FROM cves GROUP BY severity"
            ).fetchall()
            last = conn.execute(
                "SELECT timestamp FROM update_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            top = conn.execute(
                "SELECT id, cvss_score, severity FROM cves ORDER BY cvss_score DESC LIMIT 5"
            ).fetchall()
            observations = conn.execute(
                "SELECT COUNT(*), COUNT(DISTINCT source) FROM source_observations"
            ).fetchone()
            source_syncs = conn.execute(
                """
                SELECT sync.source, sync.started_at, sync.completed_at,
                       sync.success, sync.records_processed, sync.error
                FROM source_syncs AS sync
                JOIN (
                    SELECT source, MAX(id) AS latest_id
                    FROM source_syncs
                    GROUP BY source
                ) AS latest ON sync.id = latest.latest_id
                ORDER BY sync.source
                """
            ).fetchall()
        return {
            "total_cves": total,
            "source_observation_snapshots": observations[0],
            "source_observation_sources": observations[1],
            "source_syncs": [dict(row) for row in source_syncs],
            "by_severity": {r[0]: r[1] for r in sev_rows},
            "last_updated": last[0] if last else None,
            "top_critical": [dict(r) for r in top],
        }

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _parse_json_fields(d: dict, fields: list[str]) -> dict:
        for f in fields:
            if d.get(f):
                try:
                    d[f] = json.loads(d[f])
                except (json.JSONDecodeError, TypeError) as exc:
                    log.warning(
                        "Stored JSON field %s could not be decoded: %s",
                        f,
                        exc,
                    )
                    d[f] = None
        return d

    def _full(self, row) -> dict:
        d = dict(row)
        return self._parse_json_fields(
            d,
            [
                "cvss_v4",
                "cvss_v3",
                "cvss_v2",
                "affected_systems",
                "refs",
                "cwes",
                "cisa_kev",
                "ssvc",
                "sources_checked",
                "source_details",
                "source_warnings",
                "poc",
            ],
        )

    def _summary(self, row) -> dict:
        d = dict(row)
        d = self._parse_json_fields(
            d,
            [
                "cvss_v4",
                "cvss_v3",
                "cvss_v2",
                "cisa_kev",
                "ssvc",
                "sources_checked",
                "source_details",
                "source_warnings",
            ],
        )
        for f in ["affected_systems", "refs", "cwes", "poc"]:
            d.pop(f, None)
        return d

    # ------------------------------------------------------------------ #
    # User Management                                                      #
    # ------------------------------------------------------------------ #
    def create_user(self, username: str, password_hash: str) -> bool:
        """Create a new user account. Returns True on success."""
        try:
            with self._connection() as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?)",
                    (username, password_hash, datetime.now(timezone.utc).isoformat()),
                )
            return True
        except sqlite3.IntegrityError:
            log.warning("User registration failed: username '%s' already exists", username)
            return False

    def get_user(self, username: str) -> dict | None:
        """Get user by username."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
        return dict(row) if row else None

    def update_last_login(self, username: str) -> None:
        """Update user's last login timestamp."""
        with self._connection() as conn:
            conn.execute(
                "UPDATE users SET last_login = ? WHERE username = ?",
                (datetime.now(timezone.utc).isoformat(), username),
            )

    def log_failed_login(self, username: str, ip_address: str = "") -> None:
        """Log a failed login attempt."""
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO failed_logins (username, timestamp, ip_address) VALUES (?,?,?)",
                (username, datetime.now(timezone.utc).isoformat(), ip_address),
            )

    def get_failed_login_count(self, username: str, minutes_back: int = 15) -> int:
        """Get number of failed logins in the last N minutes."""
        cutoff_time = (datetime.now(timezone.utc) - timedelta(minutes=minutes_back)).isoformat()
        with self._connection() as conn:
            result = conn.execute(
                "SELECT COUNT(*) FROM failed_logins WHERE username = ? AND timestamp > ?",
                (username, cutoff_time),
            ).fetchone()
        return result[0] if result else 0

    def clear_failed_logins(self, username: str) -> None:
        """Clear failed login attempts for a user."""
        with self._connection() as conn:
            conn.execute(
                "DELETE FROM failed_logins WHERE username = ?", (username,)
            )
