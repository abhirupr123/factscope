"""Domain trust graph -- tracks historical credibility of domains over time.

Each scan updates the domain's stats in SQLite. Over time, domains
that consistently host suspicious content get penalized, and reputable
domains get boosted beyond the static list.
"""

import logging
from urllib.parse import urlparse

from db import get_domain_stats, update_domain_stats as _db_update

logger = logging.getLogger(__name__)


def extract_base_domain(url: str) -> str | None:
    try:
        netloc = urlparse(url).netloc.lower()
        if not netloc:
            return None
        parts = netloc.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return netloc
    except Exception:
        return None


def update_domain_stats(url: str, trust_score: int, verdict: str):
    """Update a domain's historical trust profile after a scan."""
    domain = extract_base_domain(url)
    if not domain:
        return
    _db_update(domain, trust_score, verdict)


def compute_domain_trust_signal(url: str) -> dict | None:
    """Return neutral historical context without changing the current assessment.

    Previous model scores and anonymous reports are neither independent evidence
    nor reliable source-quality inputs. Feeding them back into new scores creates
    a self-reinforcing loop, so this signal is display-only.
    """
    domain = extract_base_domain(url)
    if not domain:
        return None

    stats = get_domain_stats(domain)
    if not stats or stats.get("total_scans", 0) < 2:
        return None

    avg = stats.get("avg_trust_score", 50)
    total = stats.get("total_scans", 0)
    return {
        "name": "domain_history_context",
        "delta": 0,
        "detail": (
            f"Historical source-quality context: {total} previous scans "
            f"averaged {avg:.0f}/100. This does not affect the current assessment."
        ),
    }
