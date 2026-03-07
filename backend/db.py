"""Storage layer — supports local SQLite (dev) and Turso libSQL (production).

When TURSO_DATABASE_URL + TURSO_AUTH_TOKEN are set, uses an embedded replica
that syncs with Turso cloud. Otherwise falls back to plain local SQLite.

Provides:
  - Scan result storage with content fingerprint caching
  - Image scan storage and caching
  - Full-text similarity search via FTS5 + BM25 ranking
  - Domain trust statistics
  - Community flags
"""

import hashlib
import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent / "factscope.db"

_TURSO_URL = os.getenv("TURSO_DATABASE_URL")
_TURSO_TOKEN = os.getenv("TURSO_AUTH_TOKEN")
_use_turso = bool(_TURSO_URL and _TURSO_TOKEN)

_STOP_WORDS = frozenset({
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "to", "of", "in", "for",
    "on", "with", "at", "by", "from", "as", "into", "about", "that",
    "this", "it", "its", "and", "or", "but", "not", "no", "if", "than",
    "so", "up", "out", "just", "also", "more", "very", "how", "all",
    "each", "every", "both", "few", "most", "other", "some", "such",
    "only", "own", "same", "then", "when", "what", "which", "who",
    "whom", "where", "why", "after", "before", "during", "while",
    "said", "says", "according", "new", "over", "between",
})


# ═══════════════════════════════════════════════════════════════════════════════
# Connection
# ═══════════════════════════════════════════════════════════════════════════════


class _Row:
    """Row supporting both index-based and key-based access (like sqlite3.Row)."""
    __slots__ = ("_keys", "_values", "_map")

    def __init__(self, keys, values):
        self._keys = keys
        self._values = values
        self._map = dict(zip(keys, values))

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return self._map[key]

    def get(self, key, default=None):
        return self._map.get(key, default)

    def keys(self):
        return self._keys

    def __contains__(self, key):
        return key in self._map

    def items(self):
        return self._map.items()

    def values(self):
        return self._map.values()

    def __iter__(self):
        return iter(self._keys)


class _DictCursor:
    """Wraps a libsql cursor to return _Row objects instead of raw tuples."""

    def __init__(self, cursor):
        self._cursor = cursor

    def _to_row(self, raw):
        if raw is None or self._cursor.description is None:
            return raw
        cols = [d[0] for d in self._cursor.description]
        return _Row(cols, raw)

    def fetchone(self):
        return self._to_row(self._cursor.fetchone())

    def fetchall(self):
        rows = self._cursor.fetchall()
        if not rows or self._cursor.description is None:
            return rows
        cols = [d[0] for d in self._cursor.description]
        return [_Row(cols, r) for r in rows]

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def rowcount(self):
        return self._cursor.rowcount


class _TursoConn:
    """Wraps a libsql connection so queries return dict-like rows."""

    def __init__(self, raw):
        self._conn = raw

    def execute(self, sql, params=()):
        return _DictCursor(self._conn.execute(sql, params))

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()

    def sync(self):
        self._conn.sync()


def _get_conn():
    """Return a database connection (Turso cloud or local SQLite)."""
    if _use_turso:
        import libsql_experimental as libsql
        raw = libsql.connect(
            str(DB_PATH),
            sync_url=_TURSO_URL,
            auth_token=_TURSO_TOKEN,
        )
        raw.sync()
        conn = _TursoConn(raw)
    else:
        conn = sqlite3.connect(str(DB_PATH), timeout=10)
        conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _sync_and_close(conn):
    """Commit, sync to Turso if needed, then close."""
    conn.commit()
    if _use_turso:
        try:
            conn.sync()
        except Exception as exc:
            logger.debug("Turso sync failed: %s", exc)
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Schema
# ═══════════════════════════════════════════════════════════════════════════════

_SCHEMA_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS scans (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        doc_type    TEXT,
        source      TEXT,
        url         TEXT,
        fingerprint TEXT,
        trust_score INTEGER,
        verdict     TEXT,
        explanation TEXT,
        evidence    TEXT,
        judgement   TEXT,
        user_id     TEXT,
        timestamp   TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_scans_fingerprint ON scans(fingerprint)",
    "CREATE INDEX IF NOT EXISTS idx_scans_trust_score ON scans(trust_score)",

    """CREATE VIRTUAL TABLE IF NOT EXISTS scans_fts USING fts5(
        source,
        content=scans,
        content_rowid=id,
        tokenize='porter unicode61'
    )""",

    """CREATE TRIGGER IF NOT EXISTS scans_ai AFTER INSERT ON scans BEGIN
        INSERT INTO scans_fts(rowid, source) VALUES (new.id, new.source);
    END""",
    """CREATE TRIGGER IF NOT EXISTS scans_ad AFTER DELETE ON scans BEGIN
        INSERT INTO scans_fts(scans_fts, rowid, source)
            VALUES ('delete', old.id, old.source);
    END""",
    """CREATE TRIGGER IF NOT EXISTS scans_au AFTER UPDATE ON scans BEGIN
        INSERT INTO scans_fts(scans_fts, rowid, source)
            VALUES ('delete', old.id, old.source);
        INSERT INTO scans_fts(rowid, source) VALUES (new.id, new.source);
    END""",

    """CREATE TABLE IF NOT EXISTS image_scans (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        image_url           TEXT,
        url_hash            TEXT,
        authenticity_score  INTEGER,
        verdict             TEXT,
        explanation         TEXT,
        evidence            TEXT,
        claim_analysis      TEXT,
        user_id             TEXT,
        timestamp           TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_image_scans_url_hash ON image_scans(url_hash)",

    """CREATE TABLE IF NOT EXISTS domains (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        domain          TEXT UNIQUE NOT NULL,
        total_scans     INTEGER DEFAULT 0,
        avg_trust_score REAL DEFAULT 50.0,
        flag_count      INTEGER DEFAULT 0,
        last_scan       TEXT,
        last_verdict    TEXT,
        last_trust_score INTEGER
    )""",

    """CREATE TABLE IF NOT EXISTS community_flags (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        fingerprint TEXT NOT NULL,
        user_id     TEXT NOT NULL,
        reason      TEXT,
        timestamp   TEXT,
        UNIQUE(fingerprint, user_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_flags_fingerprint ON community_flags(fingerprint)",
]


def init_db():
    """Create tables and FTS index if they don't exist."""
    conn = _get_conn()
    try:
        for stmt in _SCHEMA_STATEMENTS:
            try:
                conn.execute(stmt)
            except Exception as exc:
                logger.debug("Schema statement skipped (may already exist): %s", exc)
        _sync_and_close(conn)
        logger.info("Database initialized (%s)", "Turso" if _use_turso else DB_PATH)
    except Exception as exc:
        logger.error("Failed to initialize database: %s", exc)
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Scan storage
# ═══════════════════════════════════════════════════════════════════════════════

def store_scan(doc_type: str, source, result, fingerprint: str = None,
               url: str = None, user_id: str = None):
    """Store an analysis result."""
    conn = _get_conn()
    try:
        doc = {
            "doc_type": doc_type,
            "source": str(source)[:500],
            "url": url,
            "fingerprint": fingerprint,
            "trust_score": None,
            "verdict": None,
            "explanation": None,
            "evidence": None,
            "judgement": None,
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if isinstance(result, dict):
            if "trust_score" in result:
                doc["trust_score"] = result["trust_score"]
                doc["verdict"] = result.get("verdict")
                doc["explanation"] = result.get("explanation")
                doc["evidence"] = json.dumps(result.get("evidence", []))
            if "judgement" in result:
                doc["judgement"] = result["judgement"]

        conn.execute(
            """INSERT INTO scans
               (doc_type, source, url, fingerprint, trust_score, verdict,
                explanation, evidence, judgement, user_id, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                doc["doc_type"], doc["source"], doc["url"], doc["fingerprint"],
                doc["trust_score"], doc["verdict"], doc["explanation"],
                doc["evidence"], doc["judgement"], doc["user_id"],
                doc["timestamp"],
            ),
        )
        _sync_and_close(conn)
    except Exception as exc:
        logger.warning("Failed to store scan result: %s", exc)
        conn.close()


def find_by_fingerprint(fingerprint: str) -> dict | None:
    """Return the most recent scan with this exact fingerprint, or None."""
    if not fingerprint:
        return None

    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE fingerprint = ? ORDER BY timestamp DESC LIMIT 1",
            (fingerprint,),
        ).fetchone()
        if row:
            logger.info("Fingerprint cache hit: %s", fingerprint[:16])
            doc = dict(row)
            if doc.get("evidence"):
                try:
                    doc["evidence"] = json.loads(doc["evidence"])
                except (json.JSONDecodeError, TypeError):
                    doc["evidence"] = []
            return doc
    except Exception as exc:
        logger.debug("Fingerprint lookup failed: %s", exc)
    finally:
        conn.close()
    return None


def count_scans_for_fingerprint(fingerprint: str) -> int:
    """Count how many unique users scanned content with this fingerprint."""
    if not fingerprint:
        return 0
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT COUNT(DISTINCT user_id) as cnt FROM scans WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        return row["cnt"] if row else 0
    except Exception:
        return 0
    finally:
        conn.close()


def find_flagged_similar(text: str, threshold: int = 40) -> list[dict]:
    """Find previously scanned content that is similar AND was flagged as low-trust."""
    if not text:
        return []

    keywords = _extract_search_terms(text[:500])
    if not keywords:
        return []

    conn = _get_conn()
    try:
        query = " OR ".join(keywords)
        rows = conn.execute(
            """SELECT s.* FROM scans s
               JOIN scans_fts f ON s.id = f.rowid
               WHERE scans_fts MATCH ?
                 AND s.trust_score IS NOT NULL
                 AND s.trust_score <= ?
               ORDER BY bm25(scans_fts) LIMIT 3""",
            (query, threshold),
        ).fetchall()

        results = []
        for row in rows:
            doc = dict(row)
            if doc.get("evidence"):
                try:
                    doc["evidence"] = json.loads(doc["evidence"])
                except (json.JSONDecodeError, TypeError):
                    doc["evidence"] = []
            results.append(doc)
        return results
    except Exception as exc:
        logger.debug("Flagged similarity search failed: %s", exc)
    finally:
        conn.close()
    return []


# ═══════════════════════════════════════════════════════════════════════════════
# Image scan storage
# ═══════════════════════════════════════════════════════════════════════════════

def _url_hash(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:32]


def store_image_scan(image_url: str, result: dict, user_id: str = None):
    """Store an image verification result for caching."""
    conn = _get_conn()
    try:
        conn.execute(
            """INSERT INTO image_scans
               (image_url, url_hash, authenticity_score, verdict,
                explanation, evidence, claim_analysis, user_id, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                image_url,
                _url_hash(image_url),
                result.get("authenticity_score"),
                result.get("verdict"),
                result.get("explanation"),
                json.dumps(result.get("evidence", [])),
                json.dumps(result.get("claim_analysis")) if result.get("claim_analysis") else None,
                user_id,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        _sync_and_close(conn)
    except Exception as exc:
        logger.warning("Failed to store image scan: %s", exc)
        conn.close()


def find_image_scan(image_url: str, max_age_hours: int = 24) -> dict | None:
    """Return cached image scan if it exists and isn't too old."""
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM image_scans WHERE url_hash = ? ORDER BY timestamp DESC LIMIT 1",
            (_url_hash(image_url),),
        ).fetchone()
        if row:
            doc = dict(row)
            scan_time = datetime.fromisoformat(doc["timestamp"])
            age = (datetime.now(timezone.utc) - scan_time).total_seconds() / 3600
            if age > max_age_hours:
                return None
            if doc.get("evidence"):
                try:
                    doc["evidence"] = json.loads(doc["evidence"])
                except (json.JSONDecodeError, TypeError):
                    doc["evidence"] = []
            if doc.get("claim_analysis"):
                try:
                    doc["claim_analysis"] = json.loads(doc["claim_analysis"])
                except (json.JSONDecodeError, TypeError):
                    doc["claim_analysis"] = None
            logger.info("Image cache hit: %s", image_url[:60])
            return doc
    except Exception as exc:
        logger.debug("Image scan lookup failed: %s", exc)
    finally:
        conn.close()
    return None


def count_image_verdicts(verdict: str) -> int:
    """Count how many images have been flagged with a specific verdict."""
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM image_scans WHERE verdict = ?",
            (verdict,),
        ).fetchone()
        return row["cnt"] if row else 0
    except Exception:
        return 0
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Community flags
# ═══════════════════════════════════════════════════════════════════════════════

def add_community_flag(fingerprint: str, user_id: str, reason: str = None) -> bool:
    """Flag content as misinformation. Returns True if new flag, False if duplicate."""
    if not fingerprint or not user_id:
        return False
    conn = _get_conn()
    try:
        conn.execute(
            """INSERT OR IGNORE INTO community_flags
               (fingerprint, user_id, reason, timestamp)
               VALUES (?, ?, ?, ?)""",
            (fingerprint, user_id, reason, datetime.now(timezone.utc).isoformat()),
        )
        changed = conn.execute("SELECT changes()").fetchone()[0]
        _sync_and_close(conn)
        return changed > 0
    except Exception as exc:
        logger.warning("Failed to store community flag: %s", exc)
        conn.close()
        return False


def get_flag_count(fingerprint: str) -> int:
    """Count community flags for a piece of content."""
    if not fingerprint:
        return 0
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM community_flags WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        return row["cnt"] if row else 0
    except Exception:
        return 0
    finally:
        conn.close()


def has_user_flagged(fingerprint: str, user_id: str) -> bool:
    """Check if a specific user already flagged this content."""
    if not fingerprint or not user_id:
        return False
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT 1 FROM community_flags WHERE fingerprint = ? AND user_id = ?",
            (fingerprint, user_id),
        ).fetchone()
        return row is not None
    except Exception:
        return False
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Domain stats
# ═══════════════════════════════════════════════════════════════════════════════

def get_domain_stats(domain: str) -> dict | None:
    """Fetch historical stats for a domain."""
    if not domain:
        return None

    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM domains WHERE domain = ?", (domain,)
        ).fetchone()
        return dict(row) if row else None
    except Exception as exc:
        logger.debug("Domain stats lookup failed: %s", exc)
    finally:
        conn.close()
    return None


def update_domain_stats(domain: str, trust_score: int, verdict: str):
    """Update a domain's historical trust profile after a scan."""
    if not domain:
        return

    conn = _get_conn()
    try:
        now = datetime.now(timezone.utc).isoformat()
        existing = conn.execute(
            "SELECT * FROM domains WHERE domain = ?", (domain,)
        ).fetchone()

        if existing:
            existing = dict(existing)
            total = existing.get("total_scans", 0) + 1
            old_avg = existing.get("avg_trust_score", 50)
            new_avg = round(((old_avg * (total - 1)) + trust_score) / total, 1)
            flag_count = existing.get("flag_count", 0)
            if trust_score < 40:
                flag_count += 1

            conn.execute(
                """UPDATE domains
                   SET total_scans = ?, avg_trust_score = ?, flag_count = ?,
                       last_scan = ?, last_verdict = ?, last_trust_score = ?
                   WHERE domain = ?""",
                (total, new_avg, flag_count, now, verdict, trust_score, domain),
            )
        else:
            conn.execute(
                """INSERT INTO domains
                   (domain, total_scans, avg_trust_score, flag_count,
                    last_scan, last_verdict, last_trust_score)
                   VALUES (?, 1, ?, ?, ?, ?, ?)""",
                (domain, float(trust_score), 1 if trust_score < 40 else 0,
                 now, verdict, trust_score),
            )
        _sync_and_close(conn)
    except Exception as exc:
        logger.debug("Domain stats update failed: %s", exc)
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _extract_search_terms(text: str, max_terms: int = 12) -> list[str]:
    """Pull significant words from text for an FTS5 MATCH query."""
    clean = re.sub(r"[^\w\s]", "", text).lower()
    words = [w for w in clean.split() if len(w) >= 3 and w not in _STOP_WORDS]
    seen = set()
    unique = []
    for w in words:
        if w not in seen:
            seen.add(w)
            unique.append(w)
        if len(unique) >= max_terms:
            break
    return unique


# Initialize on import
init_db()
