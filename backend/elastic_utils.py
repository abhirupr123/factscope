"""Storage utilities — thin wrappers around db.py (SQLite).

This module preserves the public API that main.py and other modules import,
but delegates everything to the SQLite backend in db.py.
"""

from db import store_scan, find_by_fingerprint, find_flagged_similar  # noqa: F401


def store_analysis_result(doc_type, source, result, fingerprint=None, url=None):
    """Store an analysis result (delegates to db.store_scan)."""
    store_scan(doc_type, source, result, fingerprint=fingerprint, url=url)
