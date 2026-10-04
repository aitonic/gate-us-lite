from __future__ import annotations

import json
import sqlite3
import statistics
import time
from pathlib import Path
from .models import Candidate, candidate_to_dict, candidate_from_dict
from .intel import INTEL_SCHEMA

SOURCE_CACHE_SCHEMA = 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS refresh_runs(
  ts INTEGER PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS source_refreshes(
  ts INTEGER NOT NULL,
  source TEXT NOT NULL,
  status TEXT NOT NULL,
  PRIMARY KEY(ts, source)
);
CREATE INDEX IF NOT EXISTS idx_source_refreshes_source_ts ON source_refreshes(source, ts DESC);
CREATE TABLE IF NOT EXISTS observations(
  ts INTEGER NOT NULL,
  endpoint_key TEXT NOT NULL,
  ip TEXT NOT NULL,
  source_family TEXT NOT NULL,
  source TEXT NOT NULL,
  present INTEGER NOT NULL DEFAULT 1,
  ping_ms REAL,
  speed_mbps REAL,
  sessions INTEGER
);
CREATE INDEX IF NOT EXISTS idx_obs_key_ts ON observations(endpoint_key, ts);
CREATE INDEX IF NOT EXISTS idx_obs_key_source_ts ON observations(endpoint_key, source, ts);
CREATE TABLE IF NOT EXISTS probe_observations(
  ts INTEGER NOT NULL,
  endpoint_key TEXT NOT NULL,
  reachable INTEGER NOT NULL,
  latency_ms REAL
);
CREATE INDEX IF NOT EXISTS idx_probe_key_ts ON probe_observations(endpoint_key, ts DESC);
CREATE TABLE IF NOT EXISTS intel_cache(
  ip TEXT PRIMARY KEY,
  fetched_at INTEGER NOT NULL,
  payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS source_state(
  source TEXT PRIMARY KEY,
  fetched_at INTEGER NOT NULL,
  ok INTEGER NOT NULL,
  message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS source_snapshots(
  source TEXT NOT NULL,
  ts INTEGER NOT NULL,
  count INTEGER NOT NULL,
  status TEXT NOT NULL,
  PRIMARY KEY(source, ts)
);
CREATE INDEX IF NOT EXISTS idx_source_snapshots ON source_snapshots(source, ts DESC);
CREATE TABLE IF NOT EXISTS source_cache(
  source TEXT PRIMARY KEY,
  fetched_at INTEGER NOT NULL,
  payload TEXT NOT NULL,
  schema_version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS selection_state(
  id INTEGER PRIMARY KEY CHECK(id=1),
  payload TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        try:
            self.path.chmod(0o600)
        except OSError:
            pass
        self.db.executescript(SCHEMA)
        self._migrate()

    def _migrate(self):
        cols = {row[1] for row in self.db.execute("PRAGMA table_info(source_cache)")}
        if "schema_version" not in cols:
            self.db.execute("ALTER TABLE source_cache ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1")

        # Historical observations prove that their corresponding source refresh was
        # successful enough to produce data. Backfill those source-aware opportunities
        # so old state immediately benefits from the fixed availability denominator.
        self.db.execute(
            """
            INSERT OR IGNORE INTO source_refreshes(ts,source,status)
            SELECT DISTINCT ts,source,'ok' FROM observations
            """
        )
        self.db.commit()

    def close(self):
        self.db.close()

    def record_source(self, source: str, ok: bool, message: str = ""):
        self.db.execute(
            "INSERT OR REPLACE INTO source_state VALUES(?,?,?,?)",
            (source, int(time.time()), int(ok), message[:500]),
        )
        self.db.commit()

    def record_source_snapshot(self, source: str, count: int, status: str):
        now = int(time.time())
        self.db.execute(
            "INSERT OR REPLACE INTO source_snapshots(source,ts,count,status) VALUES(?,?,?,?)",
            (source, now, int(count), status),
        )
        self.db.execute("DELETE FROM source_snapshots WHERE ts < ?", (now - 14 * 86400,))
        self.db.commit()

    def source_baseline(self, source: str, limit: int = 12) -> float | None:
        rows = self.db.execute(
            "SELECT count FROM source_snapshots WHERE source=? AND status='ok' ORDER BY ts DESC LIMIT ?",
            (source, int(limit)),
        ).fetchall()
        values = [int(row[0]) for row in rows if int(row[0]) > 0]
        return float(statistics.median(values)) if values else None

    def observe(self, candidates: list[Candidate], source_statuses: dict[str, str] | None = None):
        """Record fresh evidence and source refresh outcomes for this generator run.

        Availability is source-aware: error/degraded/skipped/cache-only source runs are
        not observation opportunities and therefore cannot make a healthy endpoint look
        unavailable. Cached candidates must not be passed as fresh observations.
        """
        now = int(time.time())
        statuses = dict(source_statuses or {})
        if not statuses:
            statuses = {c.source: "ok" for c in candidates}

        self.db.execute("INSERT OR IGNORE INTO refresh_runs(ts) VALUES(?)", (now,))
        self.db.executemany(
            "INSERT OR REPLACE INTO source_refreshes(ts,source,status) VALUES(?,?,?)",
            [(now, source, status) for source, status in statuses.items()],
        )

        valid = [c for c in candidates if statuses.get(c.source, "ok") == "ok"]
        self.db.executemany(
            "INSERT INTO observations(ts,endpoint_key,ip,source_family,source,present,ping_ms,speed_mbps,sessions) VALUES(?,?,?,?,?,?,?,?,?)",
            [
                (now, c.dedupe_key, c.ip_for_intel, c.source_family, c.source, 1, c.ping_ms, c.speed_mbps, c.sessions)
                for c in valid
            ],
        )
        cutoff = now - 9 * 86400
        self.db.execute("DELETE FROM observations WHERE ts < ?", (cutoff,))
        self.db.execute("DELETE FROM refresh_runs WHERE ts < ?", (cutoff,))
        self.db.execute("DELETE FROM source_refreshes WHERE ts < ?", (cutoff,))
        self.db.execute("DELETE FROM probe_observations WHERE ts < ?", (cutoff,))
        self.db.commit()

    def _eligible_refresh_count(self, key: str, start: int) -> int:
        source_rows = self.db.execute(
            "SELECT source,MIN(ts) FROM observations WHERE endpoint_key=? GROUP BY source",
            (key,),
        ).fetchall()
        eligible_ts: set[int] = set()
        for source, first_seen in source_rows:
            source_start = max(start, int(first_seen))
            rows = self.db.execute(
                "SELECT ts FROM source_refreshes WHERE source=? AND status='ok' AND ts>=?",
                (source, source_start),
            ).fetchall()
            eligible_ts.update(int(row[0]) for row in rows)
        return len(eligible_ts)

    def history(self, key: str) -> dict[str, float]:
        now = int(time.time())
        out: dict[str, float] = {}
        first_row = self.db.execute(
            "SELECT MIN(ts) FROM observations WHERE endpoint_key=?", (key,)
        ).fetchone()
        first_seen = int(first_row[0]) if first_row and first_row[0] is not None else now
        for label, seconds in (("1h", 3600), ("24h", 86400), ("7d", 604800)):
            start = max(now - seconds, first_seen)
            observed = self.db.execute(
                "SELECT COUNT(DISTINCT ts) FROM observations WHERE endpoint_key=? AND ts>=?",
                (key, start),
            ).fetchone()
            count = int(observed[0] or 0)
            expected = self._eligible_refresh_count(key, start)
            out[f"seen_{label}"] = count
            out[f"opportunities_{label}"] = expected
            if expected > 0:
                out[f"availability_{label}"] = min(1.0, count / expected)
            else:
                out[f"availability_{label}"] = 1.0 if count else 0.0
        out.update(self.probe_history(key))
        return out

    def record_probes(self, candidates: list[Candidate]):
        now = int(time.time())
        rows = [
            (now, c.dedupe_key, int(bool(c.tcp_reachable)), c.tcp_probe_ms)
            for c in candidates
            if c.profile.proto == "tcp" and c.tcp_reachable is not None
        ]
        if rows:
            self.db.executemany(
                "INSERT INTO probe_observations(ts,endpoint_key,reachable,latency_ms) VALUES(?,?,?,?)",
                rows,
            )
            self.db.commit()

    def probe_history(self, key: str) -> dict[str, float]:
        rows = self.db.execute(
            "SELECT reachable,latency_ms FROM probe_observations WHERE endpoint_key=? ORDER BY ts DESC LIMIT 5",
            (key,),
        ).fetchall()
        streak = 0
        for reachable, _ in rows:
            if int(reachable):
                break
            streak += 1
        successes = [float(lat) for reachable, lat in rows if int(reachable) and lat is not None]
        out: dict[str, float] = {"tcp_fail_streak": float(streak)}
        if successes:
            out["tcp_probe_recent_ms"] = successes[0]
        return out

    def cache_candidates(self, source: str, candidates: list[Candidate]):
        payload = json.dumps([candidate_to_dict(c) for c in candidates], separators=(",", ":"))
        self.db.execute(
            "INSERT OR REPLACE INTO source_cache(source,fetched_at,payload,schema_version) VALUES(?,?,?,?)",
            (source, int(time.time()), payload, SOURCE_CACHE_SCHEMA),
        )
        self.db.commit()

    def cached_candidates(self, source: str, max_age: int = 86400) -> list[Candidate]:
        row = self.db.execute(
            "SELECT fetched_at,payload,schema_version FROM source_cache WHERE source=?", (source,)
        ).fetchone()
        if not row or int(time.time()) - int(row[0]) > max_age:
            return []
        if int(row[2]) != SOURCE_CACHE_SCHEMA:
            return []
        return [candidate_from_dict(dict(x)) for x in json.loads(row[1])]

    def get_selection(self) -> dict:
        row = self.db.execute("SELECT payload FROM selection_state WHERE id=1").fetchone()
        return json.loads(row[0]) if row else {}

    def put_selection(self, preferred: list[Candidate], fallback: list[Candidate]):
        payload = {
            "preferred": [c.dedupe_key for c in preferred],
            "fallback": [c.dedupe_key for c in fallback],
        }
        self.db.execute(
            "INSERT OR REPLACE INTO selection_state VALUES(1,?)", (json.dumps(payload),)
        )
        self.db.commit()

    def get_intel(self, ip: str, ttl: int = 86400, error_ttl: int = 900):
        row = self.db.execute(
            "SELECT fetched_at,payload FROM intel_cache WHERE ip=?", (ip,)
        ).fetchone()
        if not row:
            return None
        payload = json.loads(row[1])
        if int(payload.get("intel_schema") or 0) != INTEL_SCHEMA:
            return None
        effective_ttl = ttl if payload.get("ipwho_status") == "ok" else error_ttl
        if int(time.time()) - int(row[0]) > effective_ttl:
            return None
        return payload

    def put_intel(self, ip: str, payload: dict):
        self.db.execute(
            "INSERT OR REPLACE INTO intel_cache VALUES(?,?,?)",
            (ip, int(time.time()), json.dumps(payload, separators=(",", ":"))),
        )
        self.db.commit()
