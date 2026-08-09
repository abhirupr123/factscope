"""
Fact-checking pipeline: LLM claim extraction + Google Fact Check API + news corroboration.

Two verification layers:
  1. Google Fact Check API -- checks if a claim was reviewed by Snopes/PolitiFact/etc.
  2. Google News RSS -- checks how many news sources are reporting the same story.
     Free, no API key, works in production.

Gracefully degrades when APIs are unavailable.
"""

import json
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlencode, quote_plus

import requests
import feedparser

from urllib.parse import urlparse, urljoin
from config import (
    GOOGLE_FACTCHECK_API_KEY, EVIDENCE_PROBE_TIMEOUT_SECONDS,
    EVIDENCE_MAX_LINKS, EVIDENCE_MAX_WORKERS,
)
from safe_fetch import safe_probe, validate_public_url, UnsafeURLError
from evidence_quality import enrich_claim_evidence

logger = logging.getLogger(__name__)


def _normalize_url(url: str) -> str:
    """Strip query params and fragment for URL comparison."""
    if not url:
        return ""
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path}".rstrip("/").lower()
    except Exception:
        return url.lower().split("?")[0].split("#")[0].rstrip("/")


def _extract_domain(url: str) -> str:
    """Extract the base domain from a URL for source matching."""
    if not url:
        return ""
    try:
        host = urlparse(url).netloc.lower()
        host = host.split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""


def _source_matches_domain(source_name: str, domain: str) -> bool:
    """Check if a news source name matches the scanned article's domain."""
    if not source_name or not domain:
        return False
    sn = source_name.lower().strip()
    base = domain.split(".")[0]
    return (
        domain in sn
        or sn in domain
        or base in sn.replace(" ", "")
        or sn.replace(" ", "") in domain
    )

FACTCHECK_API_URL = "https://factchecktools.googleapis.com/v1alpha1/claims:search"
GOOGLE_NEWS_RSS = "https://news.google.com/rss/search?q={query}&hl=en&gl=US&ceid=US:en"

CLAIM_EXTRACTION_PROMPT = """\
You are a faithful claim extractor. Given page content, identify 3-4 specific, \
verifiable factual claims that represent the article's MAIN assertions.

Respond with ONLY a JSON array of short claim strings. No markdown, no backticks.
Example: ["Claim one here", "Claim two here", "Claim three here"]

Rules:
- FOCUS ON THE MAIN ARTICLE ONLY. The text may contain sidebar content, trending stories, \
or related article snippets from the same website. IGNORE those completely. \
Only extract claims from the primary article identified by the title/headline at the top.
- Prioritize the article's PRIMARY claims — what the headline and lead paragraphs assert. \
Do not elevate minor or secondary details over the main story.
- FAITHFULNESS IS CRITICAL: preserve the original meaning exactly as stated in the text. \
Do NOT swap subjects and objects or invert who did what to whom. \
If A attacked B, say "A attacked B", never "B attacked A".
- When an event is described as a response or retaliation, include that context \
(e.g. "Iran launched retaliatory strikes" not just "Iran attacked").
- Quote or closely paraphrase the source text. Never infer or reinterpret.
- Extract only factual assertions that could be checked (names, numbers, events, dates).
- Ignore opinions, subjective statements, and hedged language ("might", "could").
- Each claim must be a self-contained sentence under 25 words.
- If the content has fewer than 2 verifiable claims, return an empty array [].
- Do NOT invent claims. Only extract what the text actually states."""

_DISPUTE_PATTERNS = re.compile(
    r"false|pants on fire|mostly false|misleading|incorrect|wrong|fabricat|debunk|hoax|fake",
    re.IGNORECASE,
)
_VERIFY_PATTERNS = re.compile(
    r"true|mostly true|correct|accurate|confirmed|verified",
    re.IGNORECASE,
)

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


def is_available() -> bool:
    """Return True if claim verification should run.
    Google News RSS needs no key, so corroboration is always available."""
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# News corroboration (Google News RSS)
# ═══════════════════════════════════════════════════════════════════════════════

def _classify_corroboration(count: int, avg_relevance: float = 1.0) -> str:
    if count == 0:
        return "not_corroborated"
    if avg_relevance < 0.4:
        return "related_topic"
    if count <= 5:
        return "lightly_reported"
    if count <= 20:
        return "multiple_sources"
    return "widely_reported"


_NOISE_WORDS = frozenset({
    "rare", "photo", "photos", "picture", "pictures", "image", "images",
    "video", "videos", "clip", "watch", "look", "see", "seen", "shows",
    "showing", "viral", "breaking", "exclusive", "shocking", "amazing",
})

def _extract_keywords(text: str, max_words: int = 8) -> str:
    """Extract significant keywords from text for a search query."""
    clean = re.sub(r"['\u2019]s\b", "", text)
    clean = re.sub(r"[-/]", " ", clean)
    clean = re.sub(r"[^\w\s]", "", clean).strip().lower()
    words = [w for w in clean.split()
             if len(w) >= 3 and w not in _STOP_WORDS and w not in _NOISE_WORDS]
    return " ".join(words[:max_words])


def _entry_published_at(entry) -> str | None:
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if not parsed:
        return None
    try:
        return datetime(*parsed[:6], tzinfo=timezone.utc).isoformat()
    except (TypeError, ValueError):
        return None


def _parse_summary_articles(summary_html: str, published_at: str | None = None) -> list[dict]:
    """Extract individual article candidates from Google News summary HTML."""
    results = []
    if not summary_html:
        return results
    a_pattern = re.compile(r'<a[^>]+href="([^"]+)"[^>]*>([^<]+)</a>\s*(?:&nbsp;)*\s*(?:<font[^>]*>([^<]*)</font>)?', re.IGNORECASE)
    for match in a_pattern.finditer(summary_html):
        url, title, source = match.group(1), match.group(2).strip(), (match.group(3) or "").strip()
        if not title or not url:
            continue
        for sep in (" | ", " - "):
            if sep in title:
                title = title.rsplit(sep, 1)[0].strip()
        resolved_url = urljoin("https://news.google.com/", url)
        results.append({
            "title": title, "url": resolved_url, "source": {"name": source},
            "published_at": published_at,
        })
    return results


def _search_news(query: str) -> list[dict]:
    """Search Google News RSS for recent article candidates."""
    if not query:
        return []

    try:
        url = GOOGLE_NEWS_RSS.format(query=quote_plus(query))
        resp = requests.get(url, timeout=6, headers={"User-Agent": "FactScope/1.0"})
        if resp.status_code != 200:
            logger.warning("Google News RSS returned %d", resp.status_code)
            return []

        feed = feedparser.parse(resp.content)
        articles = []
        seen_titles = set()
        for entry in feed.entries[:20]:
            summary = entry.get("summary", "")
            published_at = _entry_published_at(entry)
            sub_articles = _parse_summary_articles(summary, published_at=published_at)
            if sub_articles:
                for article in sub_articles:
                    title = article["title"]
                    title_key = title.casefold()
                    if title_key not in seen_titles:
                        seen_titles.add(title_key)
                        articles.append({
                            "title": title,
                            "description": "",
                            "url": article["url"],
                            "source": article["source"],
                            "published_at": article.get("published_at"),
                        })
            else:
                title = entry.get("title", "")
                source_data = entry.get("source", {})
                source_name = source_data.get("title", "") if hasattr(source_data, "get") else ""
                if not source_name and " - " in title:
                    source_name = title.rsplit(" - ", 1)[-1].strip()
                    title = title.rsplit(" - ", 1)[0].strip()
                title_key = title.casefold()
                if title and title_key not in seen_titles:
                    seen_titles.add(title_key)
                    articles.append({
                        "title": title,
                        "description": summary,
                        "url": entry.get("link", ""),
                        "source": {"name": source_name},
                        "published_at": published_at,
                    })

        logger.info("Google News RSS returned %d candidate articles", len(articles))
        return articles
    except requests.RequestException as exc:
        logger.warning("Google News RSS request failed: %s", exc)
    except Exception as exc:
        logger.warning("Google News RSS parse error: %s", exc)
    return []


def _publisher_identity(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").casefold())


def _title_tokens(value: str) -> set[str]:
    return set(_extract_keywords(value or "", max_words=20).split())


def _recency_label(published_at: str | None) -> str:
    if not published_at:
        return "unknown"
    try:
        published = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        age_days = max(0, (datetime.now(timezone.utc) - published).days)
    except (TypeError, ValueError):
        return "unknown"
    if age_days <= 7:
        return "current"
    if age_days <= 90:
        return "recent"
    return "older"

def _titles_are_syndicated(left: str, right: str) -> bool:
    left_tokens, right_tokens = _title_tokens(left), _title_tokens(right)
    if not left_tokens or not right_tokens:
        return False
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens) >= 0.82

def _match_claims_to_articles(claims: list[str], articles: list[dict],
                              source_url: str = "") -> dict[int, dict]:
    """Match claims to independent candidates and retain validation metadata."""
    source_domain = _extract_domain(source_url)
    candidates = []
    for article in articles:
        article_url = article.get("url") or ""
        source = (article.get("source") or {}).get("name") or ""
        if not source:
            source = _extract_domain(article_url)
        candidates.append({
            "title": article.get("title") or "",
            "combined": ((article.get("title") or "") + " " + (article.get("description") or "")).lower(),
            "url": article_url,
            "source": source,
            "publisher_id": _publisher_identity(source),
            "published_at": article.get("published_at"),
            "self_source": bool(source_domain and _source_matches_domain(source, source_domain)),
        })

    results = {}
    for index, claim in enumerate(claims):
        claim_keywords = set(_extract_keywords(claim, max_words=10).split())
        if len(claim_keywords) < 2:
            results[index] = {
                "source_count": 0, "corroboration": "not_corroborated",
                "average_relevance": 0.0, "related_articles": [], "rejected_articles": [],
            }
            continue

        matching_publishers = set()
        matched_articles = []
        rejection_items = []
        relevance_scores = []
        threshold = min(3, len(claim_keywords))
        for candidate in candidates:
            overlap = sum(1 for keyword in claim_keywords if keyword in candidate["combined"])
            relevance = overlap / len(claim_keywords) if claim_keywords else 0.0
            if overlap < threshold:
                if overlap >= 2 and len(rejection_items) < 5:
                    rejection_items.append({
                        "title": candidate["title"], "source": candidate["source"],
                        "url": candidate["url"], "reason": "low_relevance",
                        "relevance_score": round(relevance, 3),
                    })
                continue
            if candidate["self_source"]:
                rejection_items.append({
                    "title": candidate["title"], "source": candidate["source"],
                    "url": candidate["url"], "reason": "self_corroboration",
                    "relevance_score": round(relevance, 3),
                })
                continue
            publisher_id = candidate["publisher_id"] or "unknown"
            if publisher_id in matching_publishers:
                rejection_items.append({
                    "title": candidate["title"], "source": candidate["source"],
                    "url": candidate["url"], "reason": "duplicate_publisher",
                    "relevance_score": round(relevance, 3),
                })
                continue
            if any(_titles_are_syndicated(candidate["title"], item["title"]) for item in matched_articles):
                rejection_items.append({
                    "title": candidate["title"], "source": candidate["source"],
                    "url": candidate["url"], "reason": "syndicated_duplicate",
                    "relevance_score": round(relevance, 3),
                })
                continue
            matching_publishers.add(publisher_id)
            relevance_scores.append(relevance)
            matched_articles.append({
                "title": candidate["title"], "source": candidate["source"],
                "url": candidate["url"], "relevance_score": round(relevance, 3),
                "published_at": candidate["published_at"],
                "recency": _recency_label(candidate["published_at"]),
                "independent": True, "reachable": None,
            })

        source_count = len(matched_articles)
        average_relevance = sum(relevance_scores) / len(relevance_scores) if relevance_scores else 0.0
        results[index] = {
            "source_count": source_count,
            "corroboration": _classify_corroboration(source_count, average_relevance),
            "average_relevance": round(average_relevance, 3),
            "related_articles": matched_articles[:5],
            "rejected_articles": rejection_items[:8],
        }
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# Claim extraction
# ═══════════════════════════════════════════════════════════════════════════════

def extract_claims(text: str, title: str = "") -> list[str]:
    """Use the LLM to extract verifiable factual claims from text."""
    from llm_utils import _call_llm

    if not text or len(text.strip()) < 80:
        return []

    user_content = ""
    if title:
        user_content = f"ARTICLE TITLE: {title}\n\n"
    user_content += text[:2500]
    try:
        from config import FLAG_VALIDATION_MODEL
        raw = _call_llm(
            CLAIM_EXTRACTION_PROMPT,
            user_content,
            min_tokens=512,
            model_override=FLAG_VALIDATION_MODEL,
        )
        raw = raw.strip()
        # Find the JSON array — try from each '[' until one parses
        claims = None
        for m in re.finditer(r"\[", raw):
            substr = raw[m.start():]
            try:
                decoded, end_idx = json.JSONDecoder().raw_decode(substr)
                if isinstance(decoded, list):
                    claims = decoded
                    break
            except json.JSONDecodeError:
                continue
        if claims is None:
            logger.info("Claim extraction: no valid JSON array in LLM response")
            return []
        if not isinstance(claims, list):
            logger.info("Claim extraction: LLM returned non-list JSON")
            return []
        filtered = [str(c).strip() for c in claims if isinstance(c, str) and len(c.strip()) > 10][:4]
        logger.info("Claim extraction: found %d claims", len(filtered))
        return filtered
    except Exception as exc:
        logger.warning("Claim extraction failed: %s", exc)
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# Google Fact Check API
# ═══════════════════════════════════════════════════════════════════════════════

def _classify_rating(rating_text: str) -> str:
    """Map a fact-checker's textual rating to disputed/verified/mixed."""
    if _DISPUTE_PATTERNS.search(rating_text):
        return "disputed"
    if _VERIFY_PATTERNS.search(rating_text):
        return "verified"
    return "mixed"


def search_factcheck_api(claim: str) -> dict:
    """Query Google Fact Check API for a single claim."""
    result = {
        "claim": claim,
        "status": "no_fact_check_found",
        "source": None,
        "source_url": None,
        "rating": None,
    }

    if not GOOGLE_FACTCHECK_API_KEY:
        return result

    params = {
        "query": claim,
        "key": GOOGLE_FACTCHECK_API_KEY,
        "languageCode": "en",
        "pageSize": 3,
    }

    try:
        resp = requests.get(
            f"{FACTCHECK_API_URL}?{urlencode(params)}",
            timeout=5,
        )
        if resp.status_code != 200:
            logger.warning("Fact Check API returned status=%d", resp.status_code)
            return result

        data = resp.json()
        api_claims = data.get("claims", [])
        if not api_claims:
            return result

        best = api_claims[0]
        reviews = best.get("claimReview", [])
        if not reviews:
            return result

        review = reviews[0]
        rating_text = review.get("textualRating", "")
        result["source"] = review.get("publisher", {}).get("name")
        result["source_url"] = review.get("url")
        result["rating"] = rating_text
        result["status"] = _classify_rating(rating_text)

    except requests.RequestException as exc:
        logger.warning("Fact Check API request failed: %s", exc)

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Lightweight single-claim verification (for image captions, short posts)
# ═══════════════════════════════════════════════════════════════════════════════

def verify_image_claim(caption: str, source_url: str = "") -> list[dict]:
    """Verify a short image caption/claim directly without LLM extraction.

    Treats the caption as a single claim and checks it against Google Fact
    Check API + Google News RSS. No LLM tokens used.
    Caller is responsible for tone filtering (only pass factual captions).
    """
    if not caption or len(caption.strip()) < 10:
        return []

    claim = caption.strip()[:200]
    logger.info("Verifying one image-caption claim")

    fc_result = search_factcheck_api(claim)

    search_query = _extract_keywords(claim, max_words=10)
    articles = _search_news(search_query)

    news_result = _match_claims_to_articles([claim], articles, source_url=source_url).get(0, {})
    result = {
        "claim": claim,
        "status": fc_result.get("status", "no_fact_check_found"),
        "source": fc_result.get("source"),
        "source_url": fc_result.get("source_url"),
        "rating": fc_result.get("rating"),
        "source_count": news_result.get("source_count", 0),
        "corroboration": news_result.get("corroboration", "not_corroborated"),
        "average_relevance": news_result.get("average_relevance", 0.0),
        "related_articles": news_result.get("related_articles", []),
        "rejected_articles": news_result.get("rejected_articles", []),
    }
    logger.info(
        "Image claim evidence corr=%s sources=%d fc=%s",
        result["corroboration"], result["source_count"], result["status"],
    )
    return enrich_claim_evidence(_validate_evidence_links([result], source_url=source_url))

# ═══════════════════════════════════════════════════════════════════════════════
# Main pipeline (article-length text)
# ═══════════════════════════════════════════════════════════════════════════════

def _is_trusted_google_news_article_url(url: str) -> bool:
    """Allow only article redirects emitted by FactScope's fixed Google News feed."""
    try:
        parsed = urlparse(url)
        return bool(
            parsed.scheme == "https"
            and parsed.hostname == "news.google.com"
            and not parsed.username
            and not parsed.password
            and parsed.path.startswith("/rss/articles/")
        )
    except (TypeError, ValueError):
        return False


def _probe_evidence_url(url: str) -> tuple[bool, str, str | None]:
    """Probe arbitrary evidence strictly; handle trusted Google RSS redirects narrowly."""
    try:
        if _is_trusted_google_news_article_url(url):
            validate_public_url(url)
            with requests.get(
                url, timeout=EVIDENCE_PROBE_TIMEOUT_SECONDS,
                headers={"User-Agent": "FactScope/1.0", "Accept-Encoding": "identity"},
                allow_redirects=False, stream=True,
            ) as response:
                response.raise_for_status()
                if response.is_redirect or response.is_permanent_redirect:
                    location = response.headers.get("location")
                    if not location:
                        return False, "", "invalid_redirect"
                    # Never fetch the destination here. DNS/IP validation prevents
                    # private targets; the browser follows the trusted Google URL.
                    validate_public_url(urljoin(url, location))
                return True, url, None

        response = safe_probe(
            url, timeout=EVIDENCE_PROBE_TIMEOUT_SECONDS, max_redirects=5,
            allowed_content_prefixes=(
                "text/html", "application/xhtml+xml", "text/plain", "application/pdf",
            ),
        )
        return True, response.final_url, None
    except UnsafeURLError as exc:
        reason = "peer_unavailable" if "verify the remote network address" in str(exc) else "unsafe_or_invalid_url"
        return False, "", reason
    except requests.RequestException:
        return False, "", "unreachable"
    except Exception:
        return False, "", "unreachable"

def _validate_evidence_links(results: list[dict], source_url: str = "") -> list[dict]:
    """Resolve and validate only evidence links selected by claim matching."""
    urls = []
    for result in results:
        direct_url = result.get("source_url")
        if direct_url:
            urls.append(direct_url)
        for article in result.get("related_articles") or []:
            if article.get("url"):
                urls.append(article["url"])
    unique_urls = list(dict.fromkeys(urls))[:EVIDENCE_MAX_LINKS]
    probes: dict[str, tuple[bool, str, str | None]] = {}

    def probe(url: str) -> tuple[bool, str, str | None]:
        return _probe_evidence_url(url)

    if unique_urls:
        with ThreadPoolExecutor(max_workers=min(EVIDENCE_MAX_WORKERS, len(unique_urls))) as pool:
            future_urls = {pool.submit(probe, url): url for url in unique_urls}
            for future in as_completed(future_urls):
                url = future_urls[future]
                try:
                    probes[url] = future.result()
                except Exception:
                    probes[url] = (False, "", "unreachable")

    scanned_domain = _extract_domain(source_url)

    def is_scanned_domain(candidate_domain: str) -> bool:
        return bool(scanned_domain and candidate_domain and (
            candidate_domain == scanned_domain
            or candidate_domain.endswith("." + scanned_domain)
            or scanned_domain.endswith("." + candidate_domain)
        ))

    for result in results:
        rejections = list(result.get("rejected_articles") or [])
        direct_url = result.get("source_url")
        if result.get("status") in {"verified", "disputed", "mixed"}:
            if not direct_url:
                rejections.append({
                    "title": result.get("rating") or result.get("claim", ""),
                    "source": result.get("source"), "url": "", "reason": "missing_url",
                })
                result["status"] = "no_fact_check_found"
                result["source_reachable"] = False
            else:
                reachable, final_url, reason = probes.get(direct_url, (False, "", "unreachable"))
                final_domain = _extract_domain(final_url)
                if reachable and is_scanned_domain(final_domain):
                    reachable, reason = False, "self_corroboration"
                if reachable:
                    result["source_url"] = final_url
                    result["source_reachable"] = True
                else:
                    rejections.append({
                        "title": result.get("rating") or result.get("claim", ""),
                        "source": result.get("source"), "url": direct_url,
                        "reason": reason or "unreachable",
                    })
                    result["status"] = "no_fact_check_found"
                    result["source_url"] = None
                    result["source_reachable"] = False

        accepted = []
        seen_final_urls = set()
        seen_final_domains = set()
        for article in result.get("related_articles") or []:
            candidate_url = article.get("url") or ""
            reachable, final_url, reason = probes.get(candidate_url, (False, "", "unreachable"))
            final_domain = _extract_domain(final_url)
            if reachable and is_scanned_domain(final_domain):
                reachable, reason = False, "self_corroboration"
            normalized_final = _normalize_url(final_url)
            if reachable and normalized_final in seen_final_urls:
                reachable, reason = False, "duplicate_url"
            elif reachable and final_domain and final_domain in seen_final_domains:
                reachable, reason = False, "duplicate_publisher"
            if not reachable:
                rejections.append({
                    "title": article.get("title", ""), "source": article.get("source"),
                    "url": candidate_url, "reason": reason or "unreachable",
                    "relevance_score": article.get("relevance_score"),
                })
                continue
            seen_final_urls.add(normalized_final)
            if final_domain:
                seen_final_domains.add(final_domain)
            accepted.append({**article, "url": final_url, "reachable": True})

        result["related_articles"] = accepted[:5]
        result["source_count"] = len(accepted)
        relevance_scores = [
            float(article.get("relevance_score") or 0) for article in accepted
        ]
        average_relevance = sum(relevance_scores) / len(relevance_scores) if relevance_scores else 0.0
        result["average_relevance"] = round(average_relevance, 3)
        result["corroboration"] = _classify_corroboration(len(accepted), average_relevance)
        result["rejected_articles"] = rejections[:12]
        result["validation_summary"] = {
            "shown": len(accepted) + int(bool(result.get("source_url"))),
            "rejected": len(rejections),
        }
        rejection_reasons = {}
        for item in rejections:
            reason = str(item.get("reason") or "validation_failed")
            rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1
        logger.info(
            "Evidence validation shown=%d rejected=%d average_relevance=%.3f reasons=%s",
            result["validation_summary"]["shown"], len(rejections), average_relevance,
            rejection_reasons,
        )
    return results

_EMPTY_RESULT = {
    "status": "no_fact_check_found",
    "source": None,
    "source_url": None,
    "rating": None,
    "source_count": 0,
    "corroboration": "not_corroborated",
}

_NEWS_DEFAULT = {"source_count": 0, "corroboration": "not_corroborated", "related_articles": []}


def verify_claims(text: str, title: str = "", source_url: str = "") -> list[dict]:
    """Full pipeline: extract claims, then verify via Fact Check + Google News.

    Uses a single Google News RSS search for corroboration instead of one
    API call per claim. Google Fact Check API calls run fully in parallel.
    Filters out articles matching source_url to avoid self-citation.

    Returns a list of dicts, each with:
        claim, status, source, source_url, rating, source_count, corroboration
    """
    if not is_available():
        return []

    claims = extract_claims(text, title=title)
    if not claims:
        return []

    logger.info("Verifying %d claims via Fact Check + Google News RSS", len(claims))

    fc_results = {}
    news_results = {}

    title_query = _extract_keywords(title, max_words=8) if title else ""
    claim_query = _extract_keywords(claims[0], max_words=8)

    with ThreadPoolExecutor(max_workers=len(claims) + 2) as pool:
        fc_futures = {
            pool.submit(search_factcheck_api, claim): i
            for i, claim in enumerate(claims)
        }
        news_futures = []
        if title_query:
            news_futures.append(pool.submit(_search_news, title_query))
        if claim_query and claim_query != title_query:
            news_futures.append(pool.submit(_search_news, claim_query))
        elif not title_query:
            news_futures.append(pool.submit(_search_news, claim_query))

        for future in as_completed(fc_futures):
            idx = fc_futures[future]
            try:
                fc_results[idx] = future.result()
            except Exception as exc:
                logger.warning("FC API failed for claim %d: %s", idx + 1, exc)
                fc_results[idx] = {"claim": claims[idx], **_EMPTY_RESULT}

        try:
            all_articles = []
            seen_urls = set()
            for nf in news_futures:
                for article in nf.result():
                    url = article.get("url", "")
                    if url not in seen_urls:
                        seen_urls.add(url)
                        all_articles.append(article)
            if all_articles:
                news_results = _match_claims_to_articles(claims, all_articles, source_url=source_url)
        except Exception as exc:
            logger.warning("News corroboration pipeline failed: %s", exc)

    results = []
    for i, claim in enumerate(claims):
        fc = fc_results.get(i, {"claim": claim, **_EMPTY_RESULT})
        nr = news_results.get(i, _NEWS_DEFAULT)
        fc["source_count"] = nr["source_count"]
        fc["corroboration"] = nr["corroboration"]
        fc["related_articles"] = nr.get("related_articles", [])
        logger.info("Claim evidence result index=%d corr=%s sources=%d fc=%s",
                    i + 1, fc.get("corroboration"), fc.get("source_count", 0),
                    fc.get("status"))
        results.append(fc)

    return enrich_claim_evidence(_validate_evidence_links(results, source_url=source_url))
