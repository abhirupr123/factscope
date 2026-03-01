"""Content fingerprinting for dedup detection and cross-site tracking.

Generates a normalized hash of page content so that the same (or very similar)
content appearing on different URLs can be detected instantly.
"""

import hashlib
import re
import logging

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
