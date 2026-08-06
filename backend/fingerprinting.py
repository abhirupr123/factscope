"""Content fingerprinting for dedup detection and cross-site tracking.

Generates a normalized hash of page content so that the same (or very similar)
content appearing on different URLs can be detected instantly.
"""

import hashlib
import re
import logging
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

logger = logging.getLogger(__name__)


def normalize_text(text: str) -> str:
    """Normalize text for fingerprinting: lowercase, strip punctuation, collapse whitespace."""
    text = text.lower()
    text = re.sub(r"[^\w\s]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def compute_fingerprint(text: str) -> str | None:
    """Compute a SHA-256 fingerprint of normalized content.
    Returns None if text is too short to meaningfully fingerprint."""
    if not text or len(text) < 50:
        return None
    normalized = normalize_text(text[:2000])
    if len(normalized) < 30:
        return None
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


_BOILERPLATE_LINE = re.compile(
    r"^(?:advertisement|skip advertisement|read more|also read|subscribe|"
    r"sign in|log in|cookie settings|accept cookies|all rights reserved|"
    r"updated?\s+(?:\d+\s+)?(?:seconds?|minutes?|hours?)\s+ago)$",
    re.IGNORECASE,
)
_TRACKING_QUERY_PREFIXES = ("utm_",)
_TRACKING_QUERY_KEYS = {
    "fbclid", "gclid", "mc_cid", "mc_eid", "ref", "referrer", "source",
}


def normalize_url(url: str | None) -> str:
    """Return a stable HTTP(S) URL without fragments or tracking parameters."""
    if not url:
        return ""
    try:
        parsed = urlsplit(url.strip())
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    filtered_query = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key.lower() not in _TRACKING_QUERY_KEYS
        and not key.lower().startswith(_TRACKING_QUERY_PREFIXES)
    ]
    host = parsed.hostname.lower()
    try:
        port = parsed.port
    except ValueError:
        return ""
    if port and not (
        parsed.scheme.lower() == "http" and port == 80
        or parsed.scheme.lower() == "https" and port == 443
    ):
        host = f"{host}:{port}"
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), host, path, urlencode(filtered_query), ""))


def normalize_article_text(text: str | None, max_chars: int = 12000) -> str:
    """Remove common dynamic boilerplate before producing an exact cache hash."""
    if not text:
        return ""
    stable_lines = []
    for raw_line in text.replace("\u200b", "").splitlines():
        line = re.sub(r"\s+", " ", raw_line).strip()
        if not line or _BOILERPLATE_LINE.fullmatch(line):
            continue
        stable_lines.append(line)
    return normalize_text("\n".join(stable_lines)[:max_chars])


def compute_analysis_fingerprint(
    text: str | None,
    *,
    url: str | None = None,
    title: str | None = None,
    analysis_version: str = "1",
) -> str | None:
    """Compute a versioned cache identity from stable page content and URL."""
    stable_text = normalize_article_text(text)
    if len(stable_text) < 30:
        stable_text = normalize_text(title or "")
    if len(stable_text) < 30:
        return None
    seed = "\n".join((analysis_version, normalize_url(url), stable_text))
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()
def compute_shingles(text: str, k: int = 3) -> set[str]:
    """Compute k-word shingles for fuzzy matching."""
    words = normalize_text(text[:2000]).split()
    if len(words) < k:
        return set()
    return {" ".join(words[i : i + k]) for i in range(len(words) - k + 1)}


def jaccard_similarity(shingles_a: set[str], shingles_b: set[str]) -> float:
    """Jaccard similarity between two shingle sets (0.0 to 1.0)."""
    if not shingles_a or not shingles_b:
        return 0.0
    intersection = len(shingles_a & shingles_b)
    union = len(shingles_a | shingles_b)
    return intersection / union if union else 0.0
