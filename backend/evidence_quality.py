"""Bounded full-text relevance and stance assessment for selected evidence links."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
import re
from urllib.parse import urlsplit

import requests

from config import (
    EVIDENCE_CONTENT_MAX_BYTES, EVIDENCE_CONTENT_MAX_LINKS,
    EVIDENCE_CONTENT_TIMEOUT_SECONDS, EVIDENCE_MAX_WORKERS,
)
from safe_fetch import safe_get, UnsafeURLError, ResponseTooLargeError

_STOP = frozenset({
    "the", "and", "for", "that", "with", "from", "this", "have", "has", "had",
    "was", "were", "are", "will", "would", "could", "should", "into", "about",
    "after", "before", "over", "under", "their", "they", "them", "its", "but",
    "not", "you", "your", "his", "her", "who", "what", "when", "where", "which",
})
_DENIAL_PATTERNS = (
    "no evidence", "not true", "did not", "has not", "have not", "never happened",
    "denied", "denies", "refuted", "refutes", "false claim", "incorrect claim", "hoax",
)
_INSTRUCTION_PATTERNS = (
    "ignore previous instructions", "ignore all instructions", "system prompt",
    "assistant must", "model must", "mark this claim", "return this claim",
)
_PRIMARY_HOST_SUFFIXES = (
    ".gov", ".gov.in", ".nic.in", ".mil", "sansad.in", "parliament.uk",
    "un.org", "europa.eu",
)
_PRIMARY_PUBLISHER_TERMS = (
    "government", "ministry", "parliament", "court", "police", "commission",
    "survey of india", "press information bureau", "united nations",
)


class _VisibleTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._ignored = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {"script", "style", "noscript", "svg", "nav", "footer", "form"}:
            self._ignored += 1

    def handle_endtag(self, tag):
        if tag.lower() in {"script", "style", "noscript", "svg", "nav", "footer", "form"}:
            self._ignored = max(0, self._ignored - 1)

    def handle_data(self, data):
        if not self._ignored:
            cleaned = " ".join(data.split())
            if cleaned:
                self.parts.append(cleaned)


def _tokens(value: str) -> set[str]:
    return {
        token for token in re.findall(r"[a-z0-9]+", (value or "").casefold())
        if (len(token) >= 3 or token.isdigit()) and token not in _STOP
    }


def _numbers(value: str) -> set[str]:
    return set(re.findall(r"\b\d+(?:\.\d+)?\b", value or ""))


def _extract_text(content: bytes, content_type: str) -> str:
    if content_type.startswith("text/plain"):
        return content.decode("utf-8", errors="replace")[:60000]
    if not (content_type.startswith("text/html") or content_type.startswith("application/xhtml+xml")):
        return ""
    parser = _VisibleTextParser()
    parser.feed(content.decode("utf-8", errors="replace"))
    return " ".join(parser.parts)[:60000]


def _source_type(url: str, publisher: str, title: str) -> str:
    host = (urlsplit(url).hostname or "").casefold()
    descriptor = (publisher or "").casefold()
    if any(host == suffix.lstrip(".") or host.endswith(suffix) for suffix in _PRIMARY_HOST_SUFFIXES):
        return "primary"
    if any(term in descriptor for term in _PRIMARY_PUBLISHER_TERMS):
        return "primary"
    return "secondary"


def assess_text(claim: str, title: str, text: str, url: str = "", publisher: str = "") -> dict:
    claim_tokens = _tokens(claim)
    if len(claim_tokens) < 2 or len(text.strip()) < 80:
        return {"semantic_relevance": 0.0, "stance": "unavailable", "source_type": _source_type(url, publisher, title)}
    title_tokens = _tokens(title)
    title_coverage = len(claim_tokens & title_tokens) / len(claim_tokens)
    claim_numbers = _numbers(claim)
    best_score = 0.0
    best_sentence = ""
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", text):
        if len(sentence) < 25:
            continue
        sentence_lower = sentence.casefold()
        if any(pattern in sentence_lower for pattern in _INSTRUCTION_PATTERNS):
            continue
        sentence_tokens = _tokens(sentence)
        coverage = len(claim_tokens & sentence_tokens) / len(claim_tokens)
        score = 0.82 * coverage + 0.18 * title_coverage
        if claim_numbers and not claim_numbers.issubset(_numbers(sentence)):
            score *= 0.72
        if score > best_score:
            best_score, best_sentence = score, sentence
    best_score = round(min(1.0, best_score), 3)
    claim_lower, sentence_lower = claim.casefold(), best_sentence.casefold()
    contradiction = any(pattern in sentence_lower and pattern not in claim_lower for pattern in _DENIAL_PATTERNS)
    if best_score >= 0.62:
        stance = "contradicting" if contradiction else "corroborating"
    elif best_score >= 0.35:
        stance = "contextual"
    else:
        stance = "low_relevance"
    return {
        "semantic_relevance": best_score,
        "stance": stance,
        "source_type": _source_type(url, publisher, title),
    }


def enrich_claim_evidence(results: list[dict]) -> list[dict]:
    """Inspect strict candidates while retaining safe non-decisive context."""
    queues = [
        list(dict.fromkeys(
            article.get("url") for article in (result.get("related_articles") or [])
            if article.get("url")
        ))
        for result in results
    ]
    urls, selected = [], set()
    depth = 0
    while len(urls) < EVIDENCE_CONTENT_MAX_LINKS and any(depth < len(queue) for queue in queues):
        for queue in queues:
            if len(urls) >= EVIDENCE_CONTENT_MAX_LINKS:
                break
            if depth < len(queue) and queue[depth] not in selected:
                urls.append(queue[depth])
                selected.add(queue[depth])
        depth += 1
    fetched: dict[str, tuple[str, str] | None] = {}

    def fetch(url: str):
        try:
            response = safe_get(
                url, max_bytes=EVIDENCE_CONTENT_MAX_BYTES,
                timeout=EVIDENCE_CONTENT_TIMEOUT_SECONDS, max_redirects=2,
                allowed_content_prefixes=("text/html", "application/xhtml+xml", "text/plain"),
            )
            return _extract_text(response.content, response.content_type), response.final_url
        except (requests.RequestException, UnsafeURLError, ResponseTooLargeError, ValueError):
            return None

    if urls:
        with ThreadPoolExecutor(max_workers=min(EVIDENCE_MAX_WORKERS, len(urls))) as pool:
            futures = {pool.submit(fetch, url): url for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    fetched[url] = future.result()
                except Exception:
                    fetched[url] = None

    for result in results:
        accepted, rejected = [], list(result.get("rejected_articles") or [])
        broader_context = []
        for article in result.get("related_articles") or []:
            payload = fetched.get(article.get("url"))
            source_type = _source_type(
                article.get("url", ""), article.get("source", ""), article.get("title", "")
            )
            if not payload:
                accepted.append({
                    **article, "stance": "unavailable", "source_type": source_type,
                    "evidence_level": (
                        "matching_coverage"
                        if float(article.get("relevance_score") or 0) >= 0.5
                        else "related_context"
                    ),
                })
                continue
            text, final_url = payload
            assessment = assess_text(
                result.get("claim", ""), article.get("title", ""), text,
                final_url, article.get("source", ""),
            )
            if assessment["stance"] == "low_relevance":
                broader_context.append({
                    **article, **assessment, "url": final_url,
                    "stance": "contextual", "evidence_level": "broader_context",
                    "discovery_basis": "full_text_context",
                })
                continue
            level = (
                "corroborating" if assessment["stance"] in {"corroborating", "contradicting"}
                else "related_context"
            )
            accepted.append({**article, **assessment, "url": final_url, "evidence_level": level})

        for article in result.get("context_articles") or []:
            broader_context.append({
                **article,
                "stance": "contextual",
                "source_type": _source_type(
                    article.get("url", ""), article.get("source", ""), article.get("title", "")
                ),
                "evidence_level": "broader_context",
            })

        level_priority = {"corroborating": 0, "matching_coverage": 1, "related_context": 2}
        source_priority = {"primary": 0, "secondary": 1}
        accepted.sort(key=lambda item: (
            level_priority.get(item.get("evidence_level"), 3),
            source_priority.get(item.get("source_type"), 2),
            -float(item.get("semantic_relevance") or item.get("relevance_score") or 0),
        ))
        broader_context.sort(key=lambda item: (
            0 if item.get("discovery_basis") == "full_text_context" else 1,
            -float(item.get("semantic_relevance") or item.get("relevance_score") or 0),
        ))
        seen_urls = {item.get("url") for item in accepted}
        broader_context = [
            item for item in broader_context
            if item.get("url") and item.get("url") not in seen_urls
        ]
        supporting = [item for item in accepted if item.get("stance") == "corroborating"]
        contradicting = [item for item in accepted if item.get("stance") == "contradicting"]
        primary_support = [item for item in supporting if item.get("source_type") == "primary"]
        primary_contradiction = [item for item in contradicting if item.get("source_type") == "primary"]
        if supporting and contradicting:
            evidence_status = "mixed_reporting"
        elif len(supporting) >= 2 or primary_support:
            evidence_status = "corroborated_reporting"
        elif len(contradicting) >= 2 or primary_contradiction:
            evidence_status = "contradicted_reporting"
        else:
            evidence_status = "insufficient"
        result["related_articles"] = accepted[:5]
        result["context_articles"] = broader_context[:5]
        result["rejected_articles"] = rejected[:24]
        result["source_count"] = len(accepted)
        result["context_count"] = len(broader_context)
        result["corroborating_source_count"] = len(supporting)
        result["contradicting_source_count"] = len(contradicting)
        result["matching_coverage_count"] = sum(
            item.get("evidence_level") == "matching_coverage" for item in accepted
        )
        result["primary_source_count"] = sum(
            item.get("source_type") == "primary" for item in accepted
        )
        result["evidence_status"] = evidence_status
        summary = result.get("validation_summary") or {}
        summary["semantic_checked"] = sum(item.get("stance") != "unavailable" for item in accepted)
        summary["strict_evidence"] = len(accepted)
        summary["broader_context"] = len(broader_context)
        summary["shown"] = len(accepted) + len(broader_context) + int(bool(result.get("source_url")))
        summary["rejected"] = len(rejected)
        result["validation_summary"] = summary
    return results
