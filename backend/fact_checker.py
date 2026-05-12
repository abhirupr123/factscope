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

from urllib.parse import urlparse
from config import GOOGLE_FACTCHECK_API_KEY

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


def _parse_summary_articles(summary_html: str) -> list[dict]:
    """Extract individual article titles and URLs from Google News RSS summary HTML."""
    results = []
    if not summary_html:
        return results
    a_pattern = re.compile(r'<a[^>]+href="([^"]+)"[^>]*>([^<]+)</a>\s*(?:&nbsp;)*\s*(?:<font[^>]*>([^<]*)</font>)?', re.IGNORECASE)
    for match in a_pattern.finditer(summary_html):
        url, title, source = match.group(1), match.group(2).strip(), (match.group(3) or "").strip()
        if not title or not url:
            continue
        # Strip embedded source suffixes like "Title | India News" or "Title - Source"
        for sep in (" | ", " - "):
            if sep in title:
                title = title.rsplit(sep, 1)[0].strip()
        results.append({"title": title, "url": url, "source": {"name": source}})
    return results


def _search_news(query: str) -> list[dict]:
    """Search Google News RSS for recent articles matching query.

    Returns a list of dicts with 'title', 'source', 'url' keys
    to match the interface expected by _match_claims_to_articles.
    Parses individual articles from RSS summary HTML for accurate titles.
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
        seen_titles = set()
        for entry in feed.entries[:20]:
            summary = entry.get("summary", "")
            sub_articles = _parse_summary_articles(summary)
            if sub_articles:
                for sa in sub_articles:
                    t = sa["title"]
                    if t not in seen_titles:
                        seen_titles.add(t)
                        articles.append({
                            "title": t,
                            "description": "",
                            "url": sa["url"],
                            "source": sa["source"],
                        })
            else:
                title = entry.get("title", "")
                source_name = entry.get("source", {}).get("title", "") if hasattr(entry.get("source", {}), "get") else ""
                if not source_name and " - " in title:
                    source_name = title.rsplit(" - ", 1)[-1].strip()
                    title = title.rsplit(" - ", 1)[0].strip()
                if title and title not in seen_titles:
                    seen_titles.add(title)
                    articles.append({
                        "title": title,
                        "description": summary,
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


def _match_claims_to_articles(claims: list[str], articles: list[dict],
                              source_url: str = "") -> dict[int, dict]:
    """Match each claim to articles by keyword overlap with relevance scoring.

    For each claim, count how many articles have meaningful keyword overlap
    with the claim text. Returns {claim_index: {source_count, corroboration, related_articles}}.
    Filters out articles from the same domain as source_url (self-dedup).
    """
    source_domain = _extract_domain(source_url)

    filtered = []
    for a in articles:
        a_url = a.get("url") or ""
        source = (a.get("source") or {}).get("name") or ""
        if not source:
            try:
                source = urlparse(a_url).netloc
            except Exception:
                pass
        if source_domain and _source_matches_domain(source, source_domain):
            continue
        combined = ((a.get("title") or "") + " " + (a.get("description") or "")).lower()
        filtered.append({"title": a.get("title") or "", "combined": combined,
                         "url": a_url, "source": source})

    results = {}
    for i, claim in enumerate(claims):
        claim_keywords = set(_extract_keywords(claim, max_words=10).split())
        if len(claim_keywords) < 2:
            results[i] = {"source_count": 0, "corroboration": "not_corroborated", "related_articles": []}
            continue

        matching_sources = set()
        matched_articles = []
        relevance_scores = []
        for fa in filtered:
            overlap = sum(1 for kw in claim_keywords if kw in fa["combined"])
            if overlap >= min(3, len(claim_keywords)):
                src = fa["source"] or "unknown"
                if src not in matching_sources:
                    matching_sources.add(src)
                    relevance = overlap / len(claim_keywords) if claim_keywords else 0
                    relevance_scores.append(relevance)
                    matched_articles.append({
                        "title": fa["title"],
                        "source": src,
                        "url": fa["url"],
                    })

        source_count = len(matching_sources)
        avg_relevance = sum(relevance_scores) / len(relevance_scores) if relevance_scores else 0
        results[i] = {
            "source_count": source_count,
            "corroboration": _classify_corroboration(source_count, avg_relevance),
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

def verify_image_claim(caption: str, source_url: str = "") -> list[dict]:
    """Verify a short image caption/claim directly without LLM extraction.

    Treats the caption as a single claim and checks it against Google Fact
    Check API + Google News RSS. No LLM tokens used.
    Caller is responsible for tone filtering (only pass factual captions).
    """
    if not caption or len(caption.strip()) < 10:
        return []

    claim = caption.strip()[:200]
    logger.info("Verifying image claim directly: %s", claim[:60])

    fc_result = search_factcheck_api(claim)

    search_query = _extract_keywords(claim, max_words=10)
    articles = _search_news(search_query)

    source_domain = _extract_domain(source_url)
    matching_articles = []
    relevance_scores = []
    claim_keywords = set(_extract_keywords(claim, max_words=10).split())
    for a in articles:
        a_url = a.get("url") or ""
        source = (a.get("source") or {}).get("name") or ""
        if source_domain and _source_matches_domain(source, source_domain):
            continue
        combined = ((a.get("title") or "") + " " + (a.get("description") or "")).lower()
        overlap = sum(1 for kw in claim_keywords if kw in combined)
        if overlap >= min(2, len(claim_keywords)):
            title = a.get("title") or ""
            if title:
                relevance = overlap / len(claim_keywords) if claim_keywords else 0
                relevance_scores.append(relevance)
                matching_articles.append({"title": title, "source": source, "url": a_url})

    seen_sources = set()
    unique_articles = []
    unique_relevances = []
    for idx, ma in enumerate(matching_articles):
        if ma["source"] not in seen_sources:
            seen_sources.add(ma["source"])
            unique_articles.append(ma)
            if idx < len(relevance_scores):
                unique_relevances.append(relevance_scores[idx])

    source_count = len(unique_articles)
    avg_relevance = sum(unique_relevances) / len(unique_relevances) if unique_relevances else 0
    corr = _classify_corroboration(source_count, avg_relevance)

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

    logger.info("Image claim result: corr=%s sources=%d avg_rel=%.2f fc=%s",
                corr, source_count, avg_relevance, result["status"])
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
        logger.info("Claim %d: corr=%s sources=%d fc=%s | %s",
                    i + 1, fc.get("corroboration"), fc.get("source_count", 0),
                    fc.get("status"), claim[:50])
        results.append(fc)

    return results
