"""SQLite + FTS5 storage layer — zero-cost replacement for Elasticsearch.

Provides:
  - Scan result storage with content fingerprint caching
  - Full-text similarity search via FTS5 + BM25 ranking
  - Domain trust statistics

The database file (factscope.db) lives alongside the backend code.
No external services needed.
"""

import json
import logging
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent / "factscope.db"

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


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create tables and FTS index if they don't exist."""
    conn = _get_conn()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
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
                timestamp   TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_scans_fingerprint ON scans(fingerprint);
            CREATE INDEX IF NOT EXISTS idx_scans_trust_score ON scans(trust_score);

            CREATE VIRTUAL TABLE IF NOT EXISTS scans_fts USING fts5(
                source,
                content=scans,
                content_rowid=id,
                tokenize='porter unicode61'
            );

            -- Triggers to keep FTS index in sync
            CREATE TRIGGER IF NOT EXISTS scans_ai AFTER INSERT ON scans BEGIN
                INSERT INTO scans_fts(rowid, source) VALUES (new.id, new.source);
            END;
            CREATE TRIGGER IF NOT EXISTS scans_ad AFTER DELETE ON scans BEGIN
                INSERT INTO scans_fts(scans_fts, rowid, source)
                    VALUES ('delete', old.id, old.source);
            END;
            CREATE TRIGGER IF NOT EXISTS scans_au AFTER UPDATE ON scans BEGIN
                INSERT INTO scans_fts(scans_fts, rowid, source)
                    VALUES ('delete', old.id, old.source);
                INSERT INTO scans_fts(rowid, source) VALUES (new.id, new.source);
            END;

            CREATE TABLE IF NOT EXISTS domains (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                domain          TEXT UNIQUE NOT NULL,
                total_scans     INTEGER DEFAULT 0,
                avg_trust_score REAL DEFAULT 50.0,
                flag_count      INTEGER DEFAULT 0,
                last_scan       TEXT,
                last_verdict    TEXT,
                last_trust_score INTEGER
            );
        """)
        conn.commit()
        logger.info("SQLite database initialized at %s", DB_PATH)
    except Exception as exc:
        logger.error("Failed to initialize database: %s", exc)
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Scan storage
# ═══════════════════════════════════════════════════════════════════════════════

def store_scan(doc_type: str, source, result, fingerprint: str = None, url: str = None):
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
                explanation, evidence, judgement, timestamp)
               VALUES (:doc_type, :source, :url, :fingerprint, :trust_score,
                       :verdict, :explanation, :evidence, :judgement, :timestamp)""",
            doc,
        )
        conn.commit()
    except Exception as exc:
        logger.warning("Failed to store scan result: %s", exc)
    finally:
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


def find_flagged_similar(text: str, threshold: int = 40) -> list[dict]:
    """Find previously scanned content that is similar AND was flagged as low-trust.

    Extracts keywords from the text and uses FTS5 MATCH + BM25 ranking,
    then filters to rows with trust_score <= threshold.
    """
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
        conn.commit()
    except Exception as exc:
        logger.debug("Domain stats update failed: %s", exc)
    finally:
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
