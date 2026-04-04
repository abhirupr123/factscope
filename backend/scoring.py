"""Structural trust scoring — runs independently of the LLM.

Produces a 0-100 score based on URL reputation, content patterns,
metadata completeness, and known spam/phishing signals.
"""

from urllib.parse import urlparse

REPUTABLE_DOMAINS = frozenset({
    # International news
    "bbc.com", "bbc.co.uk", "nytimes.com", "reuters.com", "apnews.com",
    "theguardian.com", "washingtonpost.com", "npr.org", "aljazeera.com",
    "economist.com", "ft.com", "bloomberg.com", "wsj.com", "cnn.com",
    "abcnews.go.com", "nbcnews.com", "cbsnews.com", "forbes.com",
    # Indian news
    "hindustantimes.com", "timesofindia.indiatimes.com", "ndtv.com",
    "thehindu.com", "indianexpress.com", "livemint.com", "scroll.in",
    "thewire.in", "news18.com", "deccanherald.com", "telegraphindia.com",
    "business-standard.com", "moneycontrol.com",
    # Science / health
    "nature.com", "science.org", "who.int", "nih.gov", "cdc.gov",
    # Reference / govt
    "wikipedia.org", "britannica.com", "un.org", "europa.eu",
    "gov.uk", "usa.gov", "india.gov.in", "pib.gov.in",
    # Tech
    "github.com", "stackoverflow.com", "developer.mozilla.org",
    "docs.python.org", "learn.microsoft.com",
    # Entertainment / media
    "imdb.com", "rottentomatoes.com", "youtube.com",
})

SUSPICIOUS_TLDS = frozenset({
    ".tk", ".ml", ".ga", ".cf", ".click", ".download",
    ".xyz", ".top", ".buzz", ".work", ".gq", ".cam",
})

CLICKBAIT_PHRASES = [
    "you won't believe", "shocking", "this one trick",
    "doctors hate", "what they don't want you to know",
    "jaw-dropping", "mind-blowing", "insane",
]

SPAM_PHRASES = [
    "click here now", "act now", "limited time offer", "free money",
    "you have won", "congratulations", "verify your account",
    "suspended account", "tax refund", "inheritance",
    "confirm your identity", "wire transfer",
]

PHISHING_PHRASES = [
    "verify your account", "confirm your identity", "update your payment",
    "unusual activity", "click to verify", "suspended account",
    "confirm your password",
]

URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "goo.gl", "t.co",
    "short.link", "is.gd", "buff.ly", "ow.ly",
})


def compute_structural_score(
    url: str | None,
    title: str | None,
    text: str | None,
    links: list[str] | None,
    metadata: dict | None,
) -> tuple[int, list[dict]]:
    """Return (score 0-100, list of signal dicts) based on structural analysis."""
    signals: list[dict] = []
    metadata = metadata or {}

    # ── URL signals ───────────────────────────────────────────────────
    if url:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        base_domain = ".".join(domain.split(".")[-2:])

        if base_domain in REPUTABLE_DOMAINS:
            signals.append({"name": "reputable_source", "delta": 18, "detail": f"Published on {base_domain}, a trusted news source"})

        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            signals.append({"name": "suspicious_tld", "delta": -20, "detail": "Website address looks suspicious"})

        if any(s in domain for s in URL_SHORTENERS):
            signals.append({"name": "url_shortener", "delta": -10, "detail": "Link is shortened — original source hidden"})

        if len(url) > 200:
            signals.append({"name": "very_long_url", "delta": -5, "detail": "Unusually long web address"})

        if parsed.scheme == "https":
            signals.append({"name": "https", "delta": 3, "detail": "Secure connection to this site"})
        else:
            signals.append({"name": "no_https", "delta": -8, "detail": "This site does not use a secure connection"})

    # ── Content signals ───────────────────────────────────────────────
    if text:
        lower = text.lower()

        cb_hits = [p for p in CLICKBAIT_PHRASES if p in lower]
        if cb_hits:
            signals.append({"name": "clickbait", "delta": -8 * min(len(cb_hits), 3), "detail": f"Uses attention-grabbing language: \"{cb_hits[0]}\""})

        spam_hits = [p for p in SPAM_PHRASES if p in lower]
        if spam_hits:
            signals.append({"name": "spam_patterns", "delta": -12 * min(len(spam_hits), 3), "detail": f"Looks like spam: \"{spam_hits[0]}\""})

        phish_hits = [p for p in PHISHING_PHRASES if p in lower]
        if phish_hits:
            signals.append({"name": "phishing_patterns", "delta": -15 * min(len(phish_hits), 2), "detail": f"May be trying to steal info: \"{phish_hits[0]}\""})

        alpha = [c for c in text if c.isalpha()]
        if alpha and len(alpha) > 50:
            caps_ratio = sum(1 for c in alpha if c.isupper()) / len(alpha)
            if caps_ratio > 0.35:
                signals.append({"name": "excessive_caps", "delta": -8, "detail": "Too much SHOUTING — lots of capital letters"})

    if title:
        tl = title.lower()
        if any(p in tl for p in CLICKBAIT_PHRASES):
            signals.append({"name": "clickbait_title", "delta": -12, "detail": "Headline uses clickbait tactics"})
        if title == title.upper() and len(title) > 10:
            signals.append({"name": "allcaps_title", "delta": -8, "detail": "Headline is written in ALL CAPS"})

    # ── Metadata signals ──────────────────────────────────────────────
    if metadata.get("author"):
        signals.append({"name": "has_author", "delta": 5, "detail": f"Written by {metadata['author']}"})
    if metadata.get("publish_date"):
        signals.append({"name": "has_date", "delta": 4, "detail": "Has a published date"})
    if metadata.get("site_name"):
        signals.append({"name": "has_site_name", "delta": 3, "detail": f"From {metadata['site_name']}"})

    # Only penalize missing attribution on article-like pages (not databases, forums, etc.)
    page_type = metadata.get("og_type", "") or metadata.get("json_ld_type", "") or ""
    is_article_like = any(
        kw in str(page_type).lower()
        for kw in ("article", "news", "blog", "post", "story")
    )
    if (
        not metadata.get("author")
        and not metadata.get("publish_date")
        and text
        and len(text) > 500
        and is_article_like
    ):
        signals.append({"name": "no_attribution", "delta": -6, "detail": "No author or date listed for this article"})

    # ── Compute final score ───────────────────────────────────────────
    base = 60
    adjustment = sum(s["delta"] for s in signals)
    return max(0, min(100, base + adjustment)), signals
