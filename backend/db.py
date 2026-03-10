"""Storage layer — supports local SQLite (dev) and Turso libSQL (production).

When TURSO_DATABASE_URL + TURSO_AUTH_TOKEN are set, uses an embedded replica
that syncs with Turso cloud. Otherwise falls back to plain local SQLite.

Provides:
  - Scan result storage with content fingerprint caching
  - Image scan storage and caching
  - Full-text similarity search via FTS5 + BM25 ranking
  - Domain trust statistics
  - Community flags with justifications
  - Response voting (like/dislike)
  - Knowledge base (graduated community facts)
"""

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
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


_conn = None
_conn_lock = threading.Lock()


def _get_conn():
    """Return the persistent database connection, creating it on first call.

    A single connection is reused for the lifetime of the process.
    For Turso, sync only happens on startup and after writes — never on reads.
    """
    global _conn
    if _conn is not None:
        return _conn
    with _conn_lock:
        if _conn is not None:
            return _conn
        if _use_turso:
            import libsql_experimental as libsql
            raw = libsql.connect(
                str(DB_PATH),
                sync_url=_TURSO_URL,
                auth_token=_TURSO_TOKEN,
            )
            _conn = _TursoConn(raw)
        else:
            raw = sqlite3.connect(str(DB_PATH), timeout=10, check_same_thread=False)
            raw.row_factory = sqlite3.Row
            _conn = raw
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
        logger.info("Persistent DB connection created (%s)", "Turso" if _use_turso else "SQLite")
    return _conn


def _commit_and_sync():
    """Commit current transaction and sync to Turso cloud if needed."""
    conn = _get_conn()
    conn.commit()
    if _use_turso:
        try:
            conn.sync()
        except Exception as exc:
            logger.warning("Turso sync failed: %s", exc)


# ═══════════════════════════════════════════════════════════════════════════════
# Schema
# ═══════════════════════════════════════════════════════════════════════════════

VALID_FLAG_CATEGORIES = frozenset({
    "false_info", "misleading_headline", "out_of_context",
    "satire_as_real", "manipulated_media", "other",
})

_SCHEMA_STATEMENTS = [
    # ── Scans ──────────────────────────────────────────────────────────
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

    # ── Image scans ────────────────────────────────────────────────────
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

    # ── Domains ────────────────────────────────────────────────────────
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

    # ── Community flags (v2: with justification) ───────────────────────
    """CREATE TABLE IF NOT EXISTS community_flags (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        fingerprint   TEXT NOT NULL,
        user_id       TEXT NOT NULL,
        category      TEXT NOT NULL DEFAULT 'other',
        justification TEXT NOT NULL DEFAULT '',
        source_urls   TEXT,
        quality_score INTEGER DEFAULT 50,
        reason        TEXT,
        timestamp     TEXT,
        UNIQUE(fingerprint, user_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_flags_fingerprint ON community_flags(fingerprint)",

    # ── Response votes ─────────────────────────────────────────────────
    """CREATE TABLE IF NOT EXISTS response_votes (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        fingerprint TEXT NOT NULL,
        user_id     TEXT NOT NULL,
        vote        INTEGER NOT NULL,
        timestamp   TEXT,
        UNIQUE(fingerprint, user_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_votes_fingerprint ON response_votes(fingerprint)",

    # ── Knowledge base (graduated facts) ───────────────────────────────
    """CREATE TABLE IF NOT EXISTS fact_entries (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        claim_text    TEXT NOT NULL,
        counter_claim TEXT NOT NULL,
        sources       TEXT,
        category      TEXT,
        confidence    REAL DEFAULT 0.5,
        flag_count    INTEGER DEFAULT 0,
        fingerprints  TEXT,
        created_at    TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_fact_confidence ON fact_entries(confidence)",

    """CREATE VIRTUAL TABLE IF NOT EXISTS facts_fts USING fts5(
        claim_text, counter_claim,
        content=fact_entries,
        content_rowid=id,
        tokenize='porter unicode61'
    )""",
    """CREATE TRIGGER IF NOT EXISTS facts_ai AFTER INSERT ON fact_entries BEGIN
        INSERT INTO facts_fts(rowid, claim_text, counter_claim)
        VALUES (new.id, new.claim_text, new.counter_claim);
    END""",
    """CREATE TRIGGER IF NOT EXISTS facts_ad AFTER DELETE ON fact_entries BEGIN
        INSERT INTO facts_fts(facts_fts, rowid, claim_text, counter_claim)
        VALUES ('delete', old.id, old.claim_text, old.counter_claim);
    END""",

    # ── Shared results (shareable links) ───────────────────────────────
    """CREATE TABLE IF NOT EXISTS shared_results (
        id            TEXT PRIMARY KEY,
        result_type   TEXT NOT NULL DEFAULT 'page',
        score         INTEGER NOT NULL,
        verdict       TEXT NOT NULL,
        explanation   TEXT NOT NULL DEFAULT '',
        evidence      TEXT,
        domain        TEXT,
        source_info   TEXT,
        scanned_url   TEXT,
        scanned_title TEXT,
        fingerprint   TEXT,
        og_image      TEXT,
        card_png      BLOB,
        created_at    TEXT NOT NULL
    )""",
]

_MIGRATION_STATEMENTS = [
    "ALTER TABLE community_flags ADD COLUMN category TEXT DEFAULT 'other'",
    "ALTER TABLE community_flags ADD COLUMN justification TEXT DEFAULT ''",
    "ALTER TABLE community_flags ADD COLUMN source_urls TEXT",
    "ALTER TABLE community_flags ADD COLUMN quality_score INTEGER DEFAULT 50",
    "ALTER TABLE shared_results ADD COLUMN scanned_url TEXT DEFAULT ''",
    "ALTER TABLE shared_results ADD COLUMN scanned_title TEXT DEFAULT ''",
    "ALTER TABLE shared_results ADD COLUMN fingerprint TEXT",
    "ALTER TABLE shared_results ADD COLUMN og_image TEXT",
    "ALTER TABLE shared_results ADD COLUMN card_png BLOB",
]


def init_db():
    """Create tables, FTS indexes, and run migrations if needed."""
    conn = _get_conn()
    if _use_turso:
        try:
            conn.sync()
            logger.info("Turso initial sync complete")
        except Exception as exc:
            logger.warning("Turso initial sync failed: %s", exc)
    try:
        for stmt in _SCHEMA_STATEMENTS:
            try:
                conn.execute(stmt)
            except Exception as exc:
                logger.debug("Schema statement skipped (may already exist): %s", exc)
        for stmt in _MIGRATION_STATEMENTS:
            try:
                conn.execute(stmt)
            except Exception:
                pass  # column already exists
        _commit_and_sync()
        logger.info("Database initialized (%s)", "Turso" if _use_turso else DB_PATH)
    except Exception as exc:
        logger.error("Failed to initialize database: %s", exc)


# ═══════════════════════════════════════════════════════════════════════════════
# Scan storage
# ═══════════════════════════════════════════════════════════════════════════════

def store_scan(doc_type: str, source, result, fingerprint: str = None,
               url: str = None, user_id: str = None):
    """Store an analysis result."""
    try:
        conn = _get_conn()
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
        _commit_and_sync()
    except Exception as exc:
        logger.warning("Failed to store scan result: %s", exc)


def find_by_fingerprint(fingerprint: str) -> dict | None:
    """Return the most recent scan with this exact fingerprint, or None."""
    if not fingerprint:
        return None
    try:
        conn = _get_conn()
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
        logger.warning("Fingerprint lookup failed: %s", exc)
    return None


def count_scans_for_fingerprint(fingerprint: str) -> int:
    """Count how many unique users scanned content with this fingerprint."""
    if not fingerprint:
        return 0
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT COUNT(DISTINCT user_id) as cnt FROM scans WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        return row["cnt"] if row else 0
    except Exception:
        return 0


def find_flagged_similar(text: str, threshold: int = 40) -> list[dict]:
    """Find previously scanned content that is similar AND was flagged as low-trust."""
    if not text:
        return []

    keywords = _extract_search_terms(text[:500])
    if not keywords:
        return []

    try:
        conn = _get_conn()
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
    return []


def find_trusted_similar(text: str, threshold: int = 80,
                         exclude_fingerprint: str = None) -> list[dict]:
    """Find previously scanned HIGH-trust content verified by 2+ users."""
    if not text:
        return []

    keywords = _extract_search_terms(text[:500])
    if not keywords:
        return []

    try:
        conn = _get_conn()
        query = " OR ".join(keywords)
        rows = conn.execute(
            """SELECT s.fingerprint, s.trust_score, s.verdict, s.source,
                      COUNT(DISTINCT s.user_id) AS user_count
               FROM scans s
               JOIN scans_fts f ON s.id = f.rowid
               WHERE scans_fts MATCH ?
                 AND s.trust_score IS NOT NULL
                 AND s.trust_score >= ?
               GROUP BY s.fingerprint
               HAVING user_count >= 2
               ORDER BY bm25(scans_fts) LIMIT 5""",
            (query, threshold),
        ).fetchall()

        results = []
        for row in rows:
            doc = dict(row)
            if exclude_fingerprint and doc.get("fingerprint") == exclude_fingerprint:
                continue
            results.append(doc)
            if len(results) >= 3:
                break
        return results
    except Exception as exc:
        logger.debug("Trusted similarity search failed: %s", exc)
    return []


# ═══════════════════════════════════════════════════════════════════════════════
# Image scan storage
# ═══════════════════════════════════════════════════════════════════════════════

def url_hash(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:32]


def store_image_scan(image_url: str, result: dict, user_id: str = None):
    """Store an image verification result for caching."""
    try:
        conn = _get_conn()
        conn.execute(
            """INSERT INTO image_scans
               (image_url, url_hash, authenticity_score, verdict,
                explanation, evidence, claim_analysis, user_id, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                image_url,
                url_hash(image_url),
                result.get("authenticity_score"),
                result.get("verdict"),
                result.get("explanation"),
                json.dumps(result.get("evidence", [])),
                json.dumps(result.get("claim_analysis")) if result.get("claim_analysis") else None,
                user_id,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        _commit_and_sync()
    except Exception as exc:
        logger.warning("Failed to store image scan: %s", exc)


def find_image_scan(image_url: str, max_age_hours: int = 24) -> dict | None:
    """Return cached image scan if it exists and isn't too old."""
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM image_scans WHERE url_hash = ? ORDER BY timestamp DESC LIMIT 1",
            (url_hash(image_url),),
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
    return None


def count_image_verdicts(verdict: str) -> int:
    """Count how many images have been flagged with a specific verdict."""
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM image_scans WHERE verdict = ?",
            (verdict,),
        ).fetchone()
        return row["cnt"] if row else 0
    except Exception:
        return 0


# ═══════════════════════════════════════════════════════════════════════════════
# Community flags
# ═══════════════════════════════════════════════════════════════════════════════

def add_community_flag(fingerprint: str, user_id: str, category: str,
                       justification: str, source_urls: list[str] | None = None,
                       quality_score: int = 50) -> dict | None:
    """Add a community note. Returns the stored note dict, or None on failure."""
    if not fingerprint or not user_id:
        return None
    if category not in VALID_FLAG_CATEGORIES:
        category = "other"
    if not justification or len(justification.strip()) < 30:
        return None
    try:
        conn = _get_conn()
        urls_json = json.dumps(source_urls) if source_urls else None
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """INSERT OR IGNORE INTO community_flags
               (fingerprint, user_id, category, justification, source_urls,
                quality_score, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (fingerprint, user_id, category, justification.strip(), urls_json, quality_score, now),
        )
        changed = conn.execute("SELECT changes()").fetchone()[0]
        _commit_and_sync()
        if changed > 0:
            return {
                "category": category,
                "justification": justification.strip(),
                "source_urls": source_urls,
                "timestamp": now,
            }
        return None
    except Exception as exc:
        logger.warning("Failed to store community flag: %s", exc)
        return None


def get_community_notes(fingerprint: str, limit: int = 5) -> list[dict]:
    """Return community notes for a fingerprint, newest first."""
    if not fingerprint:
        return []
    try:
        conn = _get_conn()
        rows = conn.execute(
            """SELECT category, justification, source_urls, timestamp
               FROM community_flags
               WHERE fingerprint = ? AND justification != ''
               ORDER BY timestamp DESC LIMIT ?""",
            (fingerprint, limit),
        ).fetchall()
        notes = []
        for r in rows:
            note = dict(r)
            if note.get("source_urls"):
                try:
                    note["source_urls"] = json.loads(note["source_urls"])
                except (json.JSONDecodeError, TypeError):
                    note["source_urls"] = []
            else:
                note["source_urls"] = []
            notes.append(note)
        return notes
    except Exception as exc:
        logger.debug("Community notes fetch failed: %s", exc)
        return []


def get_flag_count(fingerprint: str) -> int:
    """Count community flags for a piece of content."""
    if not fingerprint:
        return 0
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM community_flags WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        return row["cnt"] if row else 0
    except Exception:
        return 0


def has_user_flagged(fingerprint: str, user_id: str) -> bool:
    """Check if a specific user already flagged this content."""
    if not fingerprint or not user_id:
        return False
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT 1 FROM community_flags WHERE fingerprint = ? AND user_id = ?",
            (fingerprint, user_id),
        ).fetchone()
        return row is not None
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# Response votes
# ═══════════════════════════════════════════════════════════════════════════════

def store_vote(fingerprint: str, user_id: str, vote: int) -> bool:
    """Store a like (+1) or dislike (-1). Returns True if new vote stored."""
    if not fingerprint or not user_id or vote not in (1, -1):
        return False
    try:
        conn = _get_conn()
        conn.execute(
            """INSERT INTO response_votes (fingerprint, user_id, vote, timestamp)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(fingerprint, user_id) DO UPDATE SET vote = ?, timestamp = ?""",
            (fingerprint, user_id, vote, datetime.now(timezone.utc).isoformat(),
             vote, datetime.now(timezone.utc).isoformat()),
        )
        _commit_and_sync()
        return True
    except Exception as exc:
        logger.warning("Failed to store vote: %s", exc)
        return False


def get_vote_stats(fingerprint: str) -> dict:
    """Return {likes, dislikes} for a fingerprint."""
    result = {"likes": 0, "dislikes": 0}
    if not fingerprint:
        return result
    try:
        conn = _get_conn()
        row = conn.execute(
            """SELECT
                 SUM(CASE WHEN vote = 1 THEN 1 ELSE 0 END) as likes,
                 SUM(CASE WHEN vote = -1 THEN 1 ELSE 0 END) as dislikes
               FROM response_votes WHERE fingerprint = ?""",
            (fingerprint,),
        ).fetchone()
        if row:
            result["likes"] = row["likes"] or 0
            result["dislikes"] = row["dislikes"] or 0
    except Exception as exc:
        logger.debug("Vote stats fetch failed: %s", exc)
    return result


def should_invalidate_cache(fingerprint: str) -> bool:
    """True if the cached result has been voted down badly enough to re-analyze."""
    stats = get_vote_stats(fingerprint)
    total = stats["likes"] + stats["dislikes"]
    if total < 3:
        return False
    return stats["dislikes"] / total > 0.6


# ═══════════════════════════════════════════════════════════════════════════════
# Knowledge base
# ═══════════════════════════════════════════════════════════════════════════════

_FLAG_GRADUATION_THRESHOLD = 3

def graduate_flags_to_fact(fingerprint: str):
    """If 3+ flags exist with a consistent category, create a knowledge base entry."""
    if not fingerprint:
        return
    try:
        conn = _get_conn()
        rows = conn.execute(
            """SELECT category, justification, source_urls
               FROM community_flags WHERE fingerprint = ? AND justification != ''""",
            (fingerprint,),
        ).fetchall()
        if len(rows) < _FLAG_GRADUATION_THRESHOLD:
            return

        categories = [dict(r)["category"] for r in rows]
        from collections import Counter
        top_cat, top_count = Counter(categories).most_common(1)[0]
        if top_count < _FLAG_GRADUATION_THRESHOLD:
            return

        existing = conn.execute(
            "SELECT 1 FROM fact_entries WHERE fingerprints LIKE ?",
            (f"%{fingerprint}%",),
        ).fetchone()
        if existing:
            return

        matching = [dict(r) for r in rows if dict(r)["category"] == top_cat]
        best = max(matching, key=lambda n: len(n["justification"]))
        all_sources = []
        for n in matching:
            if n.get("source_urls"):
                try:
                    urls = json.loads(n["source_urls"]) if isinstance(n["source_urls"], str) else n["source_urls"]
                    all_sources.extend(urls)
                except (json.JSONDecodeError, TypeError):
                    pass

        scan = conn.execute(
            "SELECT explanation, source FROM scans WHERE fingerprint = ? LIMIT 1",
            (fingerprint,),
        ).fetchone()
        claim = (dict(scan).get("explanation") or dict(scan).get("source", ""))[:500] if scan else ""
        if not claim:
            claim = f"Content flagged as {top_cat.replace('_', ' ')}"

        confidence = min(0.95, 0.5 + (len(matching) * 0.1))
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """INSERT INTO fact_entries
               (claim_text, counter_claim, sources, category, confidence,
                flag_count, fingerprints, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                claim,
                best["justification"],
                json.dumps(list(set(all_sources))[:10]) if all_sources else None,
                top_cat,
                confidence,
                len(matching),
                json.dumps([fingerprint]),
                now,
            ),
        )
        _commit_and_sync()
        logger.info("Graduated %d flags to knowledge base for %s", len(matching), fingerprint[:16])
    except Exception as exc:
        logger.warning("Flag graduation failed: %s", exc)


def search_knowledge_base(text: str, limit: int = 3) -> list[dict]:
    """Search the community knowledge base for claims matching the text."""
    if not text:
        return []
    keywords = _extract_search_terms(text[:500])
    if not keywords:
        return []
    try:
        conn = _get_conn()
        query = " OR ".join(keywords)
        rows = conn.execute(
            """SELECT f.* FROM fact_entries f
               JOIN facts_fts ft ON f.id = ft.rowid
               WHERE facts_fts MATCH ?
                 AND f.confidence >= 0.6
               ORDER BY bm25(facts_fts) LIMIT ?""",
            (query, limit),
        ).fetchall()
        results = []
        for r in rows:
            entry = dict(r)
            if entry.get("sources"):
                try:
                    entry["sources"] = json.loads(entry["sources"])
                except (json.JSONDecodeError, TypeError):
                    entry["sources"] = []
            if entry.get("fingerprints"):
                try:
                    entry["fingerprints"] = json.loads(entry["fingerprints"])
                except (json.JSONDecodeError, TypeError):
                    entry["fingerprints"] = []
            results.append(entry)
        return results
    except Exception as exc:
        logger.debug("Knowledge base search failed: %s", exc)
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# Domain stats
# ═══════════════════════════════════════════════════════════════════════════════

def get_domain_stats(domain: str) -> dict | None:
    """Fetch historical stats for a domain."""
    if not domain:
        return None
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM domains WHERE domain = ?", (domain,)
        ).fetchone()
        return dict(row) if row else None
    except Exception as exc:
        logger.debug("Domain stats lookup failed: %s", exc)
    return None


def get_domain_profile(domain: str, is_reputable: bool = False) -> dict | None:
    """Build an enriched domain profile with reputation tier and unique user count."""
    if not domain:
        return None
    try:
        conn = _get_conn()
        stats = get_domain_stats(domain)

        total_scans = 0
        avg_trust = 50.0
        flag_count = 0
        last_verdict = None

        if stats:
            total_scans = stats.get("total_scans", 0)
            avg_trust = stats.get("avg_trust_score", 50.0)
            flag_count = stats.get("flag_count", 0)
            last_verdict = stats.get("last_verdict")

        row = conn.execute(
            "SELECT COUNT(DISTINCT user_id) AS cnt FROM scans WHERE url LIKE ?",
            (f"%{domain}%",),
        ).fetchone()
        unique_users = (dict(row).get("cnt", 0) if row else 0)

        if total_scans < 2:
            tier = "new"
        elif is_reputable and avg_trust >= 60:
            tier = "trusted"
        elif avg_trust >= 80 and total_scans >= 3 and flag_count == 0:
            tier = "trusted"
        elif avg_trust >= 60 and total_scans >= 2:
            tier = "established"
        elif avg_trust < 40 and total_scans >= 2:
            tier = "low_trust"
        else:
            tier = "mixed"

        return {
            "domain": domain,
            "reputation_tier": tier,
            "is_reputable": is_reputable,
            "total_scans": total_scans,
            "unique_users": unique_users,
            "avg_trust_score": round(avg_trust, 1),
            "flag_count": flag_count,
            "last_verdict": last_verdict,
        }
    except Exception as exc:
        logger.debug("Domain profile lookup failed: %s", exc)
    return None


def update_domain_stats(domain: str, trust_score: int, verdict: str):
    """Update a domain's historical trust profile after a scan."""
    if not domain:
        return
    try:
        conn = _get_conn()
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
        _commit_and_sync()
    except Exception as exc:
        logger.debug("Domain stats update failed: %s", exc)


def update_scan_claims(fingerprint: str, judgement_json: str):
    """Update the claims/judgement field for an existing scan (used by background claim processing)."""
    if not fingerprint or not judgement_json:
        return
    try:
        conn = _get_conn()
        conn.execute(
            "UPDATE scans SET judgement = ? WHERE fingerprint = ? AND judgement IS NULL",
            (judgement_json, fingerprint),
        )
        _commit_and_sync()
        logger.info("Background claims stored for fingerprint %s", fingerprint[:16])
    except Exception as exc:
        logger.warning("Failed to update scan claims: %s", exc)


def get_scan_claims(fingerprint: str) -> str | None:
    """Retrieve the stored claims JSON for a fingerprint, or None if not yet available."""
    if not fingerprint:
        return None
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT judgement FROM scans WHERE fingerprint = ? AND judgement IS NOT NULL ORDER BY timestamp DESC LIMIT 1",
            (fingerprint,),
        ).fetchone()
        return row["judgement"] if row else None
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Shared results (shareable links)
# ═══════════════════════════════════════════════════════════════════════════════

def store_shared_result(data: dict) -> str:
    """Store a result snapshot and return an 8-char short ID.

    If a fingerprint is provided and a share link already exists for it,
    returns the existing ID instead of creating a duplicate.
    """
    import string
    import secrets as _secrets

    fp = data.get("fingerprint") or ""
    try:
        conn = _get_conn()
        if fp:
            row = conn.execute(
                "SELECT id FROM shared_results WHERE fingerprint = ?", (fp,)
            ).fetchone()
            if row:
                return row[0]

        short_id = ''.join(_secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
        conn.execute(
            """INSERT INTO shared_results
               (id, result_type, score, verdict, explanation, evidence, domain, source_info,
                scanned_url, scanned_title, fingerprint, og_image, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                short_id,
                data.get("result_type", "page"),
                int(data.get("score", 50)),
                data.get("verdict", "uncertain"),
                data.get("explanation", ""),
                json.dumps(data.get("evidence", [])),
                data.get("domain", ""),
                json.dumps(data.get("source_info")) if data.get("source_info") else None,
                data.get("scanned_url", ""),
                data.get("scanned_title", ""),
                fp or None,
                data.get("og_image", ""),
                datetime.utcnow().isoformat(),
            ),
        )
        _commit_and_sync()
        return short_id
    except Exception as exc:
        logger.error("Failed to store shared result: %s", exc)
        raise


def update_shared_card(share_id: str, card_png: bytes) -> None:
    """Store pre-generated card PNG for a shared result."""
    try:
        conn = _get_conn()
        conn.execute(
            "UPDATE shared_results SET card_png = ? WHERE id = ?",
            (card_png, share_id),
        )
        _commit_and_sync()
    except Exception as exc:
        logger.warning("Failed to update shared card: %s", exc)


def get_shared_card(share_id: str) -> bytes | None:
    """Retrieve pre-generated card PNG bytes."""
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT card_png FROM shared_results WHERE id = ?",
            (share_id,),
        ).fetchone()
        if row and row[0]:
            return bytes(row[0])
    except Exception as exc:
        logger.warning("Failed to get shared card: %s", exc)
    return None


def get_shared_result(share_id: str) -> dict | None:
    """Retrieve a shared result by its short ID."""
    if not share_id:
        return None
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM shared_results WHERE id = ?",
            (share_id,),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["evidence"] = json.loads(d["evidence"]) if d.get("evidence") else []
        d["source_info"] = json.loads(d["source_info"]) if d.get("source_info") else None
        return d
    except Exception as exc:
        logger.debug("Shared result lookup failed: %s", exc)
        return None


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
