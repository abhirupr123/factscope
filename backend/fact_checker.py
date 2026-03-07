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
from urllib.parse import urlencode, quote_plus

import requests
import feedparser

from config import GOOGLE_FACTCHECK_API_KEY

logger = logging.getLogger(__name__)

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

def _classify_corroboration(count: int) -> str:
    if count == 0:
        return "not_corroborated"
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


def _search_news(query: str) -> list[dict]:
    """Search Google News RSS for recent articles matching query.

    Returns a list of dicts with 'title', 'source', 'url' keys
    to match the interface expected by _match_claims_to_articles.
    """
    if not query:
        return []

    try:
        url = GOOGLE_NEWS_RSS.format(query=quote_plus(query))
        resp = requests.get(url, timeout=6, headers={
            "User-Agent": "FactScope/1.0",
        })
        if resp.status_code != 200:
            logger.warning("Google News RSS returned %d", resp.status_code)
            return []

        feed = feedparser.parse(resp.content)
        articles = []
        for entry in feed.entries[:20]:
            title = entry.get("title", "")
            source_name = entry.get("source", {}).get("title", "") if hasattr(entry.get("source", {}), "get") else ""
            if not source_name and " - " in title:
                source_name = title.rsplit(" - ", 1)[-1].strip()
                title = title.rsplit(" - ", 1)[0].strip()
            articles.append({
                "title": title,
                "description": entry.get("summary", ""),
                "url": entry.get("link", ""),
                "source": {"name": source_name},
            })

        logger.info("Google News RSS: %d articles for query '%s'", len(articles), query[:50])
        return articles

    except requests.RequestException as exc:
        logger.warning("Google News RSS request failed: %s", exc)
    except Exception as exc:
        logger.warning("Google News RSS parse error: %s", exc)

    return []


def _match_claims_to_articles(claims: list[str], articles: list[dict]) -> dict[int, dict]:
    """Match each claim to articles by keyword overlap.

    For each claim, count how many articles have meaningful keyword overlap
    with the claim text. Returns {claim_index: {source_count, corroboration, related_articles}}.
    """
    article_texts = []
    article_sources = []
    for a in articles:
        combined = ((a.get("title") or "") + " " + (a.get("description") or "")).lower()
        article_texts.append(combined)
        source = (a.get("source") or {}).get("name") or ""
        if not source:
            raw_url = a.get("url") or ""
            try:
                from urllib.parse import urlparse
                source = urlparse(raw_url).netloc
            except Exception:
                pass
        article_sources.append(source)

    results = {}
    for i, claim in enumerate(claims):
        claim_keywords = set(_extract_keywords(claim, max_words=10).split())
        if len(claim_keywords) < 2:
            results[i] = {"source_count": 0, "corroboration": "not_corroborated", "related_articles": []}
            continue

        matching_sources = set()
        matched_articles = []
        for j, atext in enumerate(article_texts):
            overlap = sum(1 for kw in claim_keywords if kw in atext)
            if overlap >= min(3, len(claim_keywords)):
                src = article_sources[j] or f"source_{j}"
                if src not in matching_sources:
                    matching_sources.add(src)
                    matched_articles.append({
                        "title": articles[j].get("title") or "",
                        "source": src,
                        "url": articles[j].get("url") or "",
                    })

        source_count = len(matching_sources)
        results[i] = {
            "source_count": source_count,
            "corroboration": _classify_corroboration(source_count),
            "related_articles": matched_articles[:5],
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
        raw = _call_llm(
            CLAIM_EXTRACTION_PROMPT,
            user_content,
            min_tokens=512,
        )
        raw = raw.strip()
        match = re.search(r"\[[\s\S]*\]", raw)
        if not match:
            logger.info("Claim extraction: no JSON array found in LLM response")
            return []
        claims = json.loads(match.group())
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
            logger.warning("Fact Check API returned %d for claim: %s", resp.status_code, claim[:60])
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

def verify_image_claim(caption: str) -> list[dict]:
    """Verify a short image caption/claim directly without LLM extraction.

    Treats the caption as a single claim and checks it against Google Fact
    Check API + Google News RSS. No LLM tokens used.
    Returns claim result with matching article titles/sources.
    """
    if not caption or len(caption.strip()) < 10:
        return []

    claim = caption.strip()[:200]
    logger.info("Verifying image claim directly: %s", claim[:60])

    fc_result = search_factcheck_api(claim)

    search_query = _extract_keywords(claim, max_words=10)
    articles = _search_news(search_query)

    matching_articles = []
    claim_keywords = set(_extract_keywords(claim, max_words=10).split())
    for a in articles:
        combined = ((a.get("title") or "") + " " + (a.get("description") or "")).lower()
        overlap = sum(1 for kw in claim_keywords if kw in combined)
        if overlap >= min(2, len(claim_keywords)):
            source = (a.get("source") or {}).get("name") or ""
            title = a.get("title") or ""
            url = a.get("url") or ""
            if title:
                matching_articles.append({"title": title, "source": source, "url": url})

    seen_sources = set()
    unique_articles = []
    for ma in matching_articles:
        if ma["source"] not in seen_sources:
            seen_sources.add(ma["source"])
            unique_articles.append(ma)

    source_count = len(unique_articles)
    corr = _classify_corroboration(source_count)

    result = {
        "claim": claim,
        "status": fc_result.get("status", "no_fact_check_found"),
        "source": fc_result.get("source"),
        "source_url": fc_result.get("source_url"),
        "rating": fc_result.get("rating"),
        "source_count": source_count,
        "corroboration": corr,
        "related_articles": unique_articles[:5],
    }

    logger.info("Image claim result: corr=%s sources=%d fc=%s",
                corr, source_count, result["status"])
    return [result]


# ═══════════════════════════════════════════════════════════════════════════════
# Main pipeline (article-length text)
# ═══════════════════════════════════════════════════════════════════════════════

_EMPTY_RESULT = {
    "status": "no_fact_check_found",
    "source": None,
    "source_url": None,
    "rating": None,
    "source_count": 0,
    "corroboration": "not_corroborated",
}

_NEWS_DEFAULT = {"source_count": 0, "corroboration": "not_corroborated", "related_articles": []}


def verify_claims(text: str, title: str = "") -> list[dict]:
    """Full pipeline: extract claims, then verify via Fact Check + Google News.

    Uses a single Google News RSS search for corroboration instead of one
    API call per claim. Google Fact Check API calls run fully in parallel.

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
                news_results = _match_claims_to_articles(claims, all_articles)
        except Exception as exc:
            logger.warning("News corroboration pipeline failed: %s", exc)

    results = []
    for i, claim in enumerate(claims):
        fc = fc_results.get(i, {"claim": claim, **_EMPTY_RESULT})
        nr = news_results.get(i, _NEWS_DEFAULT)
        fc["source_count"] = nr["source_count"]
        fc["corroboration"] = nr["corroboration"]
        fc["related_articles"] = nr.get("related_articles", [])
        logger.info("Claim %d: corr=%s sources=%d fc=%s | %s",
                    i + 1, fc.get("corroboration"), fc.get("source_count", 0),
                    fc.get("status"), claim[:50])
        results.append(fc)

    return results
