"""Conservative page classification for factual-verdict safeguards."""

from datetime import datetime, timezone
import re
from urllib.parse import urlsplit


CONTENT_TYPES = frozenset({
    "factual_report", "opinion", "satire", "prediction",
    "breaking_news", "other", "unsupported_page",
})

_SATIRE_RE = re.compile(r"\b(?:satire|satirical|parody|spoof)\b", re.IGNORECASE)
_SATIRE_LABEL_RE = re.compile(r"^(?:satire|parody|spoof)\s*[:\-–—]", re.IGNORECASE)
_OPINION_RE = re.compile(r"\b(?:opinion|editorial|commentary|op-ed)\b", re.IGNORECASE)
_OPINION_LABEL_RE = re.compile(r"^(?:opinion|editorial|commentary|op-ed)\s*[:\-–—]", re.IGNORECASE)
_PREDICTION_RE = re.compile(
    r"^(?:prediction|predictions|forecast|outlook|what to expect|what will happen)\b",
    re.IGNORECASE,
)
_BREAKING_RE = re.compile(
    r"^(?:breaking(?: news)?|live updates?|developing story)\s*[:\-–—]",
    re.IGNORECASE,
)
_ARTICLE_TYPES = ("article", "news", "blog", "post", "story", "report")


def _path_segments(url: str | None) -> set[str]:
    try:
        return {part.lower() for part in urlsplit(url or "").path.split("/") if part}
    except ValueError:
        return set()


def _recent_publish_date(value: str | None, hours: int = 48) -> bool:
    if not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        age_hours = (datetime.now(timezone.utc) - parsed).total_seconds() / 3600
        return -2 <= age_hours <= hours
    except (TypeError, ValueError):
        return False


def classify_page_content(
    *,
    title: str | None,
    text: str | None,
    url: str | None,
    metadata: dict | None,
    llm_result: dict | None = None,
    claims_completed: bool = False,
    fact_checks: list | None = None,
) -> dict:
    """Classify content without turning ambiguous signals into confident labels."""
    metadata = metadata or {}
    llm_result = llm_result or {}
    title = (title or "").strip()
    text = (text or "").strip()
    type_hint = " ".join(str(metadata.get(key) or "") for key in ("og_type", "json_ld_type"))
    explicit_type_hint = type_hint[:300]
    path_segments = _path_segments(url)

    content_type = "other"
    confidence = "low"
    rationale = "The page did not contain a reliable explicit content-type label."

    if len(text) < 50 and not title:
        content_type = "unsupported_page"
        confidence = "high"
        rationale = "The page did not provide enough readable content for analysis."
    elif (_SATIRE_LABEL_RE.search(title) or _SATIRE_RE.search(explicit_type_hint)
          or path_segments.intersection({"satire", "parody"})):
        content_type = "satire"
        confidence = "high"
        rationale = "The page explicitly identifies itself as satire or parody."
    elif (_OPINION_LABEL_RE.search(title) or _OPINION_RE.search(explicit_type_hint)
          or path_segments.intersection({"opinion", "editorial", "commentary", "op-ed"})):
        content_type = "opinion"
        confidence = "high"
        rationale = "The page explicitly identifies itself as opinion or commentary."
    elif _PREDICTION_RE.search(title) or path_segments.intersection({"predictions", "forecast", "outlook"}):
        content_type = "prediction"
        confidence = "high"
        rationale = "The headline or page section explicitly presents forecasts or predictions."
    elif _BREAKING_RE.search(title) or (
        "LiveBlogPosting" in type_hint and _recent_publish_date(metadata.get("publish_date"))
    ):
        content_type = "breaking_news"
        confidence = "high"
        rationale = "The page is explicitly labeled as live, breaking, or developing news."
    else:
        model_type = str(llm_result.get("content_type") or "").strip().lower()
        if model_type in CONTENT_TYPES and model_type not in {"other", "unsupported_page"}:
            content_type = model_type
            confidence = "medium"
            rationale = str(llm_result.get("classification_reason") or "The content analysis identified this page type.")[:240]
        elif any(marker in type_hint.lower() for marker in _ARTICLE_TYPES) and len(text) >= 150:
            content_type = "factual_report"
            confidence = "medium"
            rationale = "The page is labeled and structured as an article or report."
        elif len(text) >= 300:
            content_type = "other"
            confidence = "low"
            rationale = "The page has readable content but no reliable factual-report label."
        else:
            content_type = "unsupported_page"
            confidence = "medium"
            rationale = "Too little article-like content was available for reliable classification."

    model_checkability = str(llm_result.get("checkability") or "").strip().lower()
    has_claims = bool(fact_checks)
    if has_claims:
        checkability = "checkable"
    elif claims_completed:
        if model_checkability == "no_checkable_claims" or content_type in {"opinion", "satire", "prediction"}:
            checkability = "no_checkable_claims"
        else:
            checkability = "unknown"
    elif model_checkability in {"checkable", "mixed", "unknown"}:
        checkability = model_checkability
    elif content_type in {"opinion", "satire", "prediction"}:
        checkability = "mixed"
    else:
        checkability = "unknown"

    factual_verdict_allowed = (
        content_type in {"factual_report", "breaking_news", "other"}
        and checkability != "no_checkable_claims"
    )
    return {
        "content_type": content_type,
        "checkability": checkability,
        "confidence": confidence,
        "rationale": rationale,
        "factual_verdict_allowed": factual_verdict_allowed,
    }


def apply_factual_verdict_safeguard(
    score: int,
    verdict: str,
    explanation: str,
    classification: dict,
    _fact_checks: list | None = None,
) -> tuple[int, str, str]:
    """Neutralize factual verdicts when the page is not suitable for one."""
    if classification.get("factual_verdict_allowed", True):
        return score, verdict, explanation
    if verdict in {"spam", "phishing", "ai_generated"}:
        return score, verdict, explanation


    neutral_score = max(40, min(60, int(score)))
    content_type = str(classification.get("content_type", "this page")).replace("_", " ")
    note = (
        f" This appears to be {content_type}, so FactScope is not treating the "
        "source-quality assessment as a factual verdict."
    )
    return neutral_score, "unknown", (explanation.rstrip() + note).strip()