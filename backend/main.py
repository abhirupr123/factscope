import asyncio
from concurrent.futures import ThreadPoolExecutor, Future
from functools import wraps
from threading import Lock

from fastapi import FastAPI, Path as ApiPath, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import Annotated, Optional, Literal
from elastic_utils import store_analysis_result, find_by_fingerprint, get_domain_profile
from db import (store_image_scan, find_image_scan, find_image_scan_by_fingerprint, find_cached_scan, find_cached_scan_by_url, add_community_flag,
                get_flag_count, has_user_flagged, count_scans_for_fingerprint, record_scan_access,
                update_scan_claims, get_scan_claims, url_hash,
                get_community_notes, store_vote, get_vote_stats,
                VALID_FLAG_CATEGORIES,
                store_shared_result, get_shared_result,
                get_user_tier, get_daily_scan_count,
                increment_daily_scan, redeem_license_key,
                reserve_service_usage, store_telemetry_event,
                purge_expired_data, delete_installation_data)
from auth import AuthContext, SessionAuthError, authenticate_installation_token, issue_installation_session
from controls import SlidingWindowLimiter, client_ip_hash, hash_network_identity
from llm_utils import get_structured_analysis, get_image_verification
from scoring import compute_structural_score, REPUTABLE_DOMAINS
from content_classifier import classify_page_content, apply_factual_verdict_safeguard
from fingerprinting import compute_analysis_fingerprint, compute_content_signature, normalize_url
from trust_graph import update_domain_stats, compute_domain_trust_signal, extract_base_domain
from fact_checker import verify_claims as _verify_claims, verify_image_claim as _verify_image_claim, is_available as factcheck_available
from config import (FLAG_VALIDATION_MODEL, SCAN_LIMITS,
                    ADMIN_USER_IDS, ENVIRONMENT, MAX_REQUEST_BYTES,
                    CORS_ALLOWED_ORIGINS, SESSION_MINTS_PER_HOUR,
                    API_REQUESTS_PER_MINUTE, ANALYSIS_REQUESTS_PER_MINUTE,
                    CACHE_HITS_PER_HOUR, ANALYSIS_VERSION,
                    ANALYSIS_CACHE_MAX_AGE_HOURS,
                    MAX_CONCURRENT_ANALYSES, ANALYSIS_TIMEOUT_SECONDS,
                    IMAGE_ANALYSIS_TIMEOUT_SECONDS, DAILY_LLM_CALL_LIMIT,
                    FACTCHECK_TIMEOUT_SECONDS,
                    LLM_ESTIMATED_COST_USD, RAW_SCAN_RETENTION_DAYS,
                    TELEMETRY_RETENTION_DAYS,
                    RETENTION_CLEANUP_INTERVAL_SECONDS)
from safe_fetch import safe_get, UnsafeURLError, ResponseTooLargeError
import json
import re
import uvicorn
import logging
from datetime import datetime, timedelta, timezone
import time
import uuid
from pathlib import Path

logging.basicConfig(level=logging.INFO)

class RequestTooLargeError(Exception):
    pass


class RequestBodyLimitMiddleware:
    """Enforce the body limit even for chunked requests without Content-Length."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise RequestTooLargeError
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestTooLargeError:
            response = JSONResponse(
                status_code=413,
                content={"error": "request_too_large"},
            )
            await response(scope, receive, send)


logger = logging.getLogger(__name__)

app = FastAPI(
    title="FactScope API",
    version="0.10.0",
    docs_url=None if ENVIRONMENT == "production" else "/docs",
    redoc_url=None if ENVIRONMENT == "production" else "/redoc",
    openapi_url=None if ENVIRONMENT == "production" else "/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_REQUEST_BYTES)



@app.middleware("http")
async def enforce_request_limits(request: Request, call_next):
    """Reject oversized requests and add baseline browser security headers."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"error": "request_too_large"},
                )
        except ValueError:
            return JSONResponse(status_code=400, content={"error": "invalid_content_length"})

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/s/"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'"
        )
    return response


@app.middleware("http")
async def add_request_observability(request: Request, call_next):
    """Attach request IDs and emit privacy-safe structured request metrics."""
    request_id = uuid.uuid4().hex
    request.state.request_id = request_id
    started = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    response.headers["X-Request-ID"] = request_id
    logger.info(json.dumps({
        "event": "request_complete",
        "request_id": request_id,
        "method": request.method,
        "path": request.url.path,
        "status": response.status_code,
        "duration_ms": duration_ms,
    }, separators=(",", ":")))
    return response


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", uuid.uuid4().hex)


@app.exception_handler(HTTPException)
async def structured_http_error(request: Request, exc: HTTPException):
    content = dict(exc.detail) if isinstance(exc.detail, dict) else {
        "error": "request_failed", "message": str(exc.detail)
    }
    content["request_id"] = _request_id(request)
    return JSONResponse(status_code=exc.status_code, content=content, headers=exc.headers)


@app.exception_handler(RequestValidationError)
async def structured_validation_error(request: Request, exc: RequestValidationError):
    del exc
    return JSONResponse(status_code=422, content={"error": "validation_error", "message": "The request payload is invalid", "request_id": _request_id(request)})


@app.exception_handler(Exception)
async def structured_internal_error(request: Request, exc: Exception):
    logger.exception("Unhandled request failure: %s", type(exc).__name__)
    return JSONResponse(status_code=500, content={"error": "internal_error", "message": "The request could not be completed", "request_id": _request_id(request)})

LLM_WEIGHT = 0.65
STRUCTURAL_WEIGHT = 0.35

_bg_pool = ThreadPoolExecutor(max_workers=3)
_access_pool = ThreadPoolExecutor(max_workers=1)
_session_mint_limiter = SlidingWindowLimiter()
_api_burst_limiter = SlidingWindowLimiter()
_analysis_burst_limiter = SlidingWindowLimiter()
_cache_hit_limiter = SlidingWindowLimiter()
_analysis_semaphore = asyncio.Semaphore(MAX_CONCURRENT_ANALYSES)
_inflight_guard = Lock()
_inflight_page_analyses: dict[str, Future] = {}


def _record_scan_access_async(fingerprint: str | None, subject_id: str, result_type: str) -> None:
    if fingerprint:
        _access_pool.submit(record_scan_access, fingerprint, subject_id, result_type)


def _flush_scan_accesses() -> None:
    """Wait for access writes queued before a deletion request."""
    _access_pool.submit(lambda: None).result(timeout=ANALYSIS_TIMEOUT_SECONDS)

def _claim_page_analysis(key: str) -> tuple[Future, bool]:
    """Return a shared future and whether this request owns provider startup."""
    with _inflight_guard:
        existing = _inflight_page_analyses.get(key)
        if existing is not None:
            return existing, False
        ready = Future()
        _inflight_page_analyses[key] = ready
        return ready, True


def _publish_page_analysis(key: str, ready: Future, llm_future: Future, fact_future: Future | None) -> None:
    if not ready.done():
        ready.set_result((llm_future, fact_future))


def _fail_page_analysis(key: str, ready: Future, exc: Exception) -> None:
    if not ready.done():
        ready.set_exception(exc)
    with _inflight_guard:
        if _inflight_page_analyses.get(key) is ready:
            _inflight_page_analyses.pop(key, None)


def _finish_page_analysis(key: str, ready: Future) -> None:
    with _inflight_guard:
        if _inflight_page_analyses.get(key) is ready:
            _inflight_page_analyses.pop(key, None)


def _burst_error(retry_after: int) -> HTTPException:
    return HTTPException(status_code=429, detail={"error": "burst_limited", "message": "Too many requests; retry shortly"}, headers={"Retry-After": str(retry_after)})


def _require_session(request: Request) -> AuthContext:
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=401,
            detail={"error": "authentication_required", "message": "A valid installation session is required"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        context = authenticate_installation_token(token)
    except SessionAuthError as exc:
        raise HTTPException(
            status_code=401,
            detail={"error": exc.code, "message": exc.message},
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    for key in (f"session:{context.token_hash}", f"ip:{client_ip_hash(request)}"):
        allowed, retry_after = _api_burst_limiter.hit(key, API_REQUESTS_PER_MINUTE, 60)
        if not allowed:
            raise _burst_error(retry_after)
    return context


def _enforce_analysis_burst(request: Request, context: AuthContext) -> None:
    for key in (f"session:{context.token_hash}", f"ip:{client_ip_hash(request)}"):
        allowed, retry_after = _analysis_burst_limiter.hit(
            key, ANALYSIS_REQUESTS_PER_MINUTE, 60
        )
        if not allowed:
            raise _burst_error(retry_after)


def _limit_analysis_capacity(function):
    @wraps(function)
    async def wrapper(*args, **kwargs):
        try:
            await asyncio.wait_for(_analysis_semaphore.acquire(), timeout=0.05)
        except TimeoutError:
            raise HTTPException(
                status_code=503,
                detail={"error": "server_busy", "message": "Analysis capacity is busy; please retry shortly"},
                headers={"Retry-After": "3"},
            )
        try:
            return await function(*args, **kwargs)
        finally:
            _analysis_semaphore.release()
    return wrapper


def _reserve_llm_call() -> int:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    allowed, count = reserve_service_usage("llm_calls", today, DAILY_LLM_CALL_LIMIT)
    if not allowed:
        raise HTTPException(
            status_code=503,
            detail={"error": "budget_exhausted", "message": "Analysis is temporarily unavailable; please try again later"},
            headers={"Retry-After": "3600"},
        )
    logger.info("Provider usage reserved: calls=%d estimated_cost_usd=%.4f", count, count * LLM_ESTIMATED_COST_USD)
    return count


@app.post("/v1/session")
async def create_installation_session(request: Request):
    """Issue a signed, anonymous installation session to the extension."""
    allowed, retry_after = _session_mint_limiter.hit(
        client_ip_hash(request), SESSION_MINTS_PER_HOUR, 3600
    )
    if not allowed:
        raise _burst_error(retry_after)
    token, context = issue_installation_session()
    return {
        "token_type": "Bearer",
        "access_token": token,
        "expires_at": context.expires_at,
    }

class TelemetryRequest(BaseModel):
    event: str = Field(min_length=1, max_length=40)


@app.post("/v1/telemetry")
async def record_telemetry(payload: TelemetryRequest, request: Request):
    """Store an allowlisted event name only; no scan content or URLs."""
    subject_id = _require_session(request).subject_id
    if not store_telemetry_event(subject_id, payload.event):
        raise HTTPException(
            status_code=422,
            detail={"error": "unsupported_telemetry_event", "message": "Unsupported telemetry event"},
        )
    return {"success": True}


@app.delete("/v1/data")
async def delete_server_data(request: Request):
    """Delete user data while retaining minimal, expiring anti-abuse records."""
    subject_id = _require_session(request).subject_id
    await asyncio.to_thread(_flush_scan_accesses)
    deleted = await asyncio.to_thread(
        delete_installation_data,
        subject_id,
        preserve_security_records=True,
    )
    logger.info(json.dumps({"event": "installation_data_deleted", "deleted": deleted}, separators=(",", ":")))
    return {"success": True, "deleted": deleted}


def _check_rate_limit(uid: str) -> dict | None:
    """Return None if under limit, or an error dict if over."""
    if uid in ADMIN_USER_IDS:
        return None
    tier = get_user_tier(uid)
    limit = SCAN_LIMITS.get(tier, SCAN_LIMITS["free"])
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    count = get_daily_scan_count(uid, today)
    if count >= limit:
        tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).replace(
            hour=0, minute=0, second=0, microsecond=0
        ).isoformat()
        logger.info(json.dumps({"event": "daily_quota_rejected", "subject": hash_network_identity(uid), "tier": tier, "used": count, "limit": limit}, separators=(",", ":")))
        return {
            "error": "rate_limited",
            "tier": tier,
            "used": count,
            "limit": limit,
            "resets_at": tomorrow,
        }
    return None


def _remaining_scans(uid: str) -> int:
    if uid in ADMIN_USER_IDS:
        return 999
    tier = get_user_tier(uid)
    limit = SCAN_LIMITS.get(tier, SCAN_LIMITS["free"])
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return max(0, limit - get_daily_scan_count(uid, today))


def _increment_and_get_remaining(uid: str) -> int:
    if uid in ADMIN_USER_IDS:
        return 999
    tier = get_user_tier(uid)
    limit = SCAN_LIMITS.get(tier, SCAN_LIMITS["free"])
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    new_count = increment_daily_scan(uid, today)
    return max(0, limit - new_count)


def _enforce_cache_hit_limit(uid: str) -> None:
    if uid in ADMIN_USER_IDS:
        return
    allowed, retry_after = _cache_hit_limiter.hit(
        hash_network_identity(uid), CACHE_HITS_PER_HOUR, 3600
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={"error": "cache_request_limited", "message": "Too many cached-result requests; retry later"},
            headers={"Retry-After": str(retry_after)},
        )


def _log_cache(request: Request, status: str, fingerprint: str | None, reason: str) -> None:
    logger.info(json.dumps({
        "event": "analysis_cache",
        "request_id": _request_id(request),
        "status": status,
        "reason": reason,
        "fingerprint": fingerprint[:16] if fingerprint else None,
        "analysis_version": ANALYSIS_VERSION,
    }, separators=(",", ":")))


class VideoInfo(BaseModel):
    platform: Optional[str] = None
    title: Optional[str] = None
    channel: Optional[str] = None
    description: Optional[str] = None
    ai_platform: Optional[bool] = None
    platform_name: Optional[str] = None
    embed_src: Optional[str] = None
    video_count: Optional[int] = None


class PageMetadata(BaseModel):
    author: Optional[str] = None
    publish_date: Optional[str] = None
    description: Optional[str] = None
    og_type: Optional[str] = None
    site_name: Optional[str] = None
    og_image: Optional[str] = Field(default=None, max_length=2048)
    canonical_url: Optional[str] = Field(default=None, max_length=2048)
    json_ld_type: Optional[str] = None


class AnalyzeRequest(BaseModel):
    url: Optional[str] = Field(default=None, max_length=2048)
    title: Optional[str] = Field(default=None, max_length=500)
    text: Optional[str] = Field(default=None, max_length=100000)
    links: Optional[list[str]] = None
    metadata: Optional[PageMetadata] = None
    video_info: Optional[VideoInfo] = None
    sample_img: Optional[str] = None
    user_id: Optional[str] = None


class SourceInfo(BaseModel):
    site_name: Optional[str] = None
    author: Optional[str] = None
    publish_date: Optional[str] = None
    domain: Optional[str] = None


class RelatedArticle(BaseModel):
    title: str
    source: Optional[str] = None
    url: Optional[str] = None


class FactCheckResult(BaseModel):
    claim: str
    status: str
    source: Optional[str] = None
    source_url: Optional[str] = None
    rating: Optional[str] = None
    source_count: Optional[int] = None
    corroboration: Optional[str] = None
    related_articles: Optional[list[RelatedArticle]] = None


class CommunityNote(BaseModel):
    category: str
    justification: str
    source_urls: Optional[list[str]] = None
    timestamp: Optional[str] = None


class VoteStats(BaseModel):
    likes: int = 0
    dislikes: int = 0


class DomainProfile(BaseModel):
    domain: str
    reputation_tier: str
    is_reputable: bool = False
    total_scans: int = 0
    unique_users: int = 0
    avg_trust_score: float = 50.0
    flag_count: int = 0
    last_verdict: Optional[str] = None


class ContentClassification(BaseModel):
    content_type: Literal[
        "factual_report", "opinion", "satire", "prediction",
        "breaking_news", "other", "unsupported_page",
    ]
    checkability: Literal["checkable", "mixed", "no_checkable_claims", "unknown"]
    confidence: Literal["low", "medium", "high"]
    rationale: str
    factual_verdict_allowed: bool

class V1SourceQualitySignal(BaseModel):
    name: str
    category: Literal["provenance", "presentation", "safety", "reputation", "technical", "context"]
    direction: Literal["positive", "negative", "neutral"]
    detail: str


class V1SourceQualityAssessment(BaseModel):
    level: Literal["low", "medium", "high", "unknown"]
    score: int
    summary: str
    signals: list[V1SourceQualitySignal] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class AnalyzeResponse(BaseModel):
    trust_score: int
    verdict: str
    explanation: str
    evidence: list[str]
    source_info: Optional[SourceInfo] = None
    domain_profile: Optional[DomainProfile] = None
    structural_signals: Optional[list[dict]] = None
    fact_checks: Optional[list[FactCheckResult]] = None
    cached: Optional[bool] = None
    cache_status: Optional[str] = None
    analysis_version: Optional[str] = None
    community_flags: Optional[int] = None
    community_scans: Optional[int] = None
    community_notes: Optional[list[CommunityNote]] = None
    vote_stats: Optional[VoteStats] = None
    kb_matches: Optional[list[dict]] = None
    fingerprint: Optional[str] = None
    claims_pending: Optional[bool] = None
    scans_remaining: Optional[int] = None
    content_classification: Optional[ContentClassification] = None
    source_quality: Optional[V1SourceQualityAssessment] = None


class V1EvidenceSource(BaseModel):
    title: str
    publisher: Optional[str] = None
    url: Optional[str] = None


class V1ClaimResult(BaseModel):
    claim: str
    status: Literal["supported", "contradicted", "mixed", "insufficient_evidence"]
    confidence: Literal["low", "medium", "high"]
    supporting_sources: list[V1EvidenceSource] = Field(default_factory=list)
    contradicting_sources: list[V1EvidenceSource] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class V1FactualEvidenceAssessment(BaseModel):
    status: Literal[
        "supported", "contradicted", "mixed", "insufficient_evidence",
        "processing", "not_applicable",
    ]
    confidence: Literal["low", "medium", "high"]
    summary: str
    claim_count: int = 0
    supported_count: int = 0
    contradicted_count: int = 0
    mixed_count: int = 0
    insufficient_count: int = 0


class V1AnalyzeResponse(AnalyzeResponse):
    schema_version: Literal["1.0"] = "1.0"
    analysis_id: str
    processing_state: Literal["processing", "partial", "complete", "failed"]
    retryable: bool = False
    overall_evidence_summary: str
    confidence: Literal["low", "medium", "high"]
    claims: list[V1ClaimResult] = Field(default_factory=list)
    factual_evidence: V1FactualEvidenceAssessment
    source_quality: V1SourceQualityAssessment
    limitations: list[str] = Field(default_factory=list)
    legacy_score: int
    legacy_verdict: str


class V1ClaimsResponse(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    analysis_id: str
    processing_state: Literal["processing", "complete", "failed"]
    claims: list[V1ClaimResult] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


def _deduplicate_v1_sources(sources: list[V1EvidenceSource]) -> list[V1EvidenceSource]:
    unique = []
    seen = set()
    for source in sources:
        key = (source.url or "", source.publisher or "", source.title)
        if key in seen:
            continue
        seen.add(key)
        unique.append(source)
    return unique


def _map_v1_claim(fact_check: FactCheckResult) -> V1ClaimResult:
    """Conservatively map legacy corroboration data into the v1 claim model."""
    direct_source = []
    if fact_check.source_url:
        direct_source.append(V1EvidenceSource(
            title=fact_check.rating or fact_check.claim[:160],
            publisher=fact_check.source,
            url=fact_check.source_url,
        ))
    related_sources = [
        V1EvidenceSource(title=article.title, publisher=article.source, url=article.url)
        for article in (fact_check.related_articles or [])
        if article.url
    ]
    limitations = []
    supporting = []
    contradicting = []

    if fact_check.status == "verified":
        status = "supported"
        confidence = "high" if direct_source else "medium"
        supporting = direct_source
        if related_sources:
            limitations.append(
                "Related coverage was found but was not classified as direct supporting evidence."
            )
    elif fact_check.status == "disputed":
        status = "contradicted"
        confidence = "high" if direct_source else "medium"
        contradicting = direct_source
        if related_sources:
            limitations.append(
                "Related coverage was found but was not classified as contradicting evidence."
            )
    elif fact_check.status == "mixed":
        status = "mixed"
        confidence = "medium" if direct_source else "low"
        limitations.append("The available fact-check rating was mixed or context-dependent.")
    else:
        status = "insufficient_evidence"
        confidence = "low"
        if fact_check.status == "opinion":
            limitations.append("This statement appears to be opinion or rhetoric rather than a checkable fact.")
        elif related_sources:
            limitations.append(
                "Related reporting was found but was not classified as supporting evidence."
            )
        else:
            limitations.append("No direct supporting or contradicting evidence was found.")

    return V1ClaimResult(
        claim=fact_check.claim,
        status=status,
        confidence=confidence,
        supporting_sources=_deduplicate_v1_sources(supporting),
        contradicting_sources=_deduplicate_v1_sources(contradicting),
        limitations=limitations,
    )


def _provider_failed(legacy: AnalyzeResponse) -> bool:
    explanation = (legacy.explanation or "").lower()
    return legacy.verdict == "unknown" and any(marker in explanation for marker in (
        "provider was unavailable", "analysis timed out", "could not complete the analysis",
    ))


def _source_signal_category(name: str) -> str:
    lowered = (name or "").lower()
    if any(token in lowered for token in ("author", "date", "site_name", "attribution")):
        return "provenance"
    if any(token in lowered for token in ("phishing", "spam", "ai_video", "suspicious")):
        return "safety"
    if any(token in lowered for token in ("domain", "reputable", "tld")):
        return "reputation"
    if any(token in lowered for token in ("https", "url", "shortener")):
        return "technical"
    if any(token in lowered for token in ("clickbait", "caps", "title", "content")):
        return "presentation"
    return "context"


def _build_source_quality_assessment(
    score: int,
    structural_signals: Optional[list[dict]],
) -> V1SourceQualityAssessment:
    safe_score = max(0, min(100, int(score)))
    if safe_score >= 75:
        level = "high"
        summary = "The page shows relatively strong source, safety, and presentation signals."
    elif safe_score < 45:
        level = "low"
        summary = "The page shows weak or concerning source, safety, or presentation signals."
    else:
        level = "medium"
        summary = "The page shows a mixture of source, safety, and presentation signals."

    mapped_signals = []
    for signal in structural_signals or []:
        delta = signal.get("delta", 0)
        mapped_signals.append(V1SourceQualitySignal(
            name=str(signal.get("name") or "source_context"),
            category=_source_signal_category(str(signal.get("name") or "")),
            direction="positive" if delta > 0 else "negative" if delta < 0 else "neutral",
            detail=str(signal.get("detail") or "Source context was observed."),
        ))

    limitations = [
        "Source quality describes the page and publisher signals; it does not establish whether individual claims are true."
    ]
    if not mapped_signals:
        limitations.append("Detailed source-quality signals were unavailable for this response.")
    return V1SourceQualityAssessment(
        level=level,
        score=safe_score,
        summary=summary,
        signals=mapped_signals,
        limitations=limitations,
    )


def _build_factual_evidence_assessment(
    claims: list[V1ClaimResult],
    processing_state: str,
    classification: Optional[ContentClassification],
) -> V1FactualEvidenceAssessment:
    counts = {
        "supported": sum(claim.status == "supported" for claim in claims),
        "contradicted": sum(claim.status == "contradicted" for claim in claims),
        "mixed": sum(claim.status == "mixed" for claim in claims),
        "insufficient": sum(claim.status == "insufficient_evidence" for claim in claims),
    }
    common = {
        "claim_count": len(claims),
        "supported_count": counts["supported"],
        "contradicted_count": counts["contradicted"],
        "mixed_count": counts["mixed"],
        "insufficient_count": counts["insufficient"],
    }

    if classification and not classification.factual_verdict_allowed:
        return V1FactualEvidenceAssessment(
            status="not_applicable",
            confidence="low",
            summary="FactScope did not assign an overall factual status to this type of content.",
            **common,
        )
    if processing_state == "processing":
        return V1FactualEvidenceAssessment(
            status="processing",
            confidence="low",
            summary="Claim-level evidence is still being processed.",
            **common,
        )
    if not claims:
        return V1FactualEvidenceAssessment(
            status="insufficient_evidence",
            confidence="low",
            summary="No claim-level evidence was available for an overall factual assessment.",
            **common,
        )

    decisive_kinds = int(counts["supported"] > 0) + int(counts["contradicted"] > 0)
    if counts["mixed"] or decisive_kinds > 1 or (
        counts["insufficient"] and (counts["supported"] or counts["contradicted"])
    ):
        status = "mixed"
        summary = "The checked claims have mixed outcomes or incomplete evidence."
    elif counts["supported"]:
        status = "supported"
        summary = "The available direct evidence supports the checked claim or claims."
    elif counts["contradicted"]:
        status = "contradicted"
        summary = "The available direct evidence contradicts the checked claim or claims."
    else:
        status = "insufficient_evidence"
        summary = "The available evidence is not sufficient to support or contradict the checked claims."

    claim_confidences = [claim.confidence for claim in claims]
    if status == "insufficient_evidence" or processing_state != "complete":
        confidence = "low"
    elif claim_confidences and all(value == "high" for value in claim_confidences):
        confidence = "high"
    else:
        confidence = "medium"

    return V1FactualEvidenceAssessment(
        status=status,
        confidence=confidence,
        summary=summary,
        **common,
    )


def _to_v1_analysis(legacy: AnalyzeResponse, fallback_analysis_id: str) -> V1AnalyzeResponse:
    claims = [_map_v1_claim(item) for item in (legacy.fact_checks or [])]
    provider_failed = _provider_failed(legacy)
    classification = legacy.content_classification
    classification_complete = bool(classification and (
        classification.content_type == "unsupported_page"
        or classification.checkability == "no_checkable_claims"
    ))
    limitations = [
        "The legacy score includes model judgment and structural website signals; it is not a probability that the content is true."
    ]

    if legacy.claims_pending:
        processing_state = "processing"
        retryable = provider_failed
        limitations.append("Claim-level evidence is still being processed.")
        if provider_failed:
            limitations.append("The main analysis provider failed; retry after claim processing completes.")
    elif provider_failed and claims:
        processing_state = "partial"
        retryable = True
        limitations.append("The main analysis provider failed, but some claim evidence was available.")
    elif provider_failed:
        processing_state = "failed"
        retryable = True
        limitations.append("The analysis provider was unavailable; no factual verdict should be inferred.")
    elif classification_complete:
        processing_state = "complete"
        retryable = False
        limitations.append("This content was classified without a claim-level factual verdict.")
    elif legacy.fact_checks is None:
        processing_state = "partial"
        retryable = False
        limitations.append("Claim-level verification was unavailable for this response.")
    else:
        processing_state = "complete"
        retryable = False
        if not claims:
            limitations.append("No checkable claims were identified in the extracted content.")

    if any(claim.status == "insufficient_evidence" for claim in claims):
        limitations.append("At least one claim lacks enough evidence for a supported or contradicted status.")

    if classification:
        if not classification.factual_verdict_allowed:
            label = classification.content_type.replace("_", " ")
            limitations.append(
                f"The page is classified as {label}; that classification does not mean it is false."
            )
        if classification.checkability == "no_checkable_claims":
            limitations.append("The extracted content did not provide claims suitable for factual verification.")

    factual_evidence = _build_factual_evidence_assessment(
        claims, processing_state, classification
    )
    source_quality = legacy.source_quality or _build_source_quality_assessment(
        legacy.trust_score, legacy.structural_signals
    )
    legacy_payload = legacy.model_dump()
    legacy_payload.pop("source_quality", None)
    analysis_id = legacy.fingerprint or fallback_analysis_id
    return V1AnalyzeResponse(
        **legacy_payload,
        analysis_id=analysis_id,
        processing_state=processing_state,
        retryable=retryable,
        overall_evidence_summary=factual_evidence.summary,
        confidence=factual_evidence.confidence,
        claims=claims,
        factual_evidence=factual_evidence,
        source_quality=source_quality,
        limitations=limitations,
        legacy_score=legacy.trust_score,
        legacy_verdict=legacy.verdict,
    )


class FlagRequest(BaseModel):
    fingerprint: str = Field(min_length=16, max_length=128)
    user_id: Optional[str] = None
    category: str
    justification: str = Field(min_length=30, max_length=500)
    source_urls: Optional[list[str]] = None


class FlagResponse(BaseModel):
    success: bool
    flag_count: int
    already_flagged: bool = False
    note: Optional[CommunityNote] = None
    rejection_reason: Optional[str] = None


class VoteRequest(BaseModel):
    fingerprint: str
    user_id: Optional[str] = None
    vote: int


class VoteResponse(BaseModel):
    success: bool
    likes: int = 0
    dislikes: int = 0


class ImageVerifyRequest(BaseModel):
    image_url: str = Field(min_length=8, max_length=2048)
    page_url: Optional[str] = Field(default=None, max_length=2048)
    page_text: Optional[str] = Field(default=None, max_length=5000)
    social_context: Optional[dict] = None
    user_id: Optional[str] = None


class ImageVerifyResponse(BaseModel):
    authenticity_score: int
    verdict: str
    explanation: str
    evidence: list[str]
    claim_analysis: Optional[list[FactCheckResult]] = None
    fingerprint: Optional[str] = None
    community_flags: Optional[int] = None
    community_notes: Optional[list[CommunityNote]] = None
    vote_stats: Optional[VoteStats] = None
    cached: Optional[bool] = None
    cache_status: Optional[str] = None
    analysis_version: Optional[str] = None
    scans_remaining: Optional[int] = None


MAX_IMAGE_BYTES = 1_500_000  # ~1.5 MB limit to keep tokens low
MAX_IMAGE_DIM = 1024


def _crop_bottom_edge(image_data: bytes) -> bytes | None:
    """Crop and enlarge the bottom 12% of an image to make watermarks readable."""
    try:
        from PIL import Image
        from io import BytesIO

        img = Image.open(BytesIO(image_data))
        w, h = img.size
        crop_h = max(60, int(h * 0.12))
        bottom = img.crop((0, h - crop_h, w, h))

        scale = max(2, 400 // crop_h)
        bottom = bottom.resize((w * scale, crop_h * scale), Image.LANCZOS)

        buf = BytesIO()
        bottom.save(buf, format="JPEG", quality=90)
        return buf.getvalue()
    except Exception:
        return None


def _fetch_and_resize_image(url: str) -> tuple[bytes, str] | tuple[None, None]:
    """Fetch an image from URL and resize to save LLM tokens."""
    from io import BytesIO

    try:
        fetched = safe_get(
            url,
            max_bytes=5_000_000,
            timeout=10,
            max_redirects=3,
            allowed_content_prefixes=("image/",),
        )
        raw = fetched.content
        content_type = fetched.content_type or "image/jpeg"

        try:
            from PIL import Image
            Image.MAX_IMAGE_PIXELS = 20_000_000
            img = Image.open(BytesIO(raw))
            w, h = img.size
            if w <= 0 or h <= 0 or w * h > 20_000_000:
                logger.warning("Image dimensions are unsafe: %sx%s", w, h)
                return None, None
            img.load()
            if img.mode in {"RGBA", "P", "LA"}:
                img = img.convert("RGB")

            if max(w, h) > MAX_IMAGE_DIM:
                ratio = MAX_IMAGE_DIM / max(w, h)
                img = img.resize((int(w * ratio), int(h * ratio)), Image.LANCZOS)

            buf = BytesIO()
            img.save(buf, format="JPEG", quality=80)
            return buf.getvalue(), "image/jpeg"
        except ImportError:
            if len(raw) > MAX_IMAGE_BYTES:
                logger.warning("Pillow not installed, image too large for raw send")
                return None, None
            return raw, content_type

    except (UnsafeURLError, ResponseTooLargeError) as exc:
        logger.warning("Blocked unsafe image fetch: %s", exc)
        return None, None
    except Exception as exc:
        logger.warning("Image fetch error: %s", exc)
        return None, None


@app.post("/analyze/verify-image")
@_limit_analysis_capacity
async def verify_image(request: ImageVerifyRequest, http_request: Request):
    """Verify an image for AI generation, manipulation, or misuse."""
    auth = _require_session(http_request)
    subject_id = auth.subject_id

    img_fp = f"img:{url_hash(request.image_url)}"

    cached = find_image_scan(
        request.image_url,
        max_age_hours=ANALYSIS_CACHE_MAX_AGE_HOURS,
        analysis_version=ANALYSIS_VERSION,
    )
    if cached:
        _enforce_cache_hit_limit(subject_id)
        _log_cache(http_request, "hit", img_fp, "fresh_versioned_image_entry")
        _record_scan_access_async(img_fp, subject_id, "image")
        img_flags = get_flag_count(img_fp)
        img_notes_raw = get_community_notes(img_fp, limit=3)
        img_notes = [CommunityNote(**n) for n in img_notes_raw] if img_notes_raw else None
        img_v_stats = get_vote_stats(img_fp)
        return ImageVerifyResponse(
            authenticity_score=cached.get("authenticity_score", 50),
            verdict=cached.get("verdict", "uncertain"),
            explanation=cached.get("explanation", ""),
            evidence=cached.get("evidence", []),
            claim_analysis=[FactCheckResult(**c) for c in cached["claim_analysis"]]
            if cached.get("claim_analysis") else None,
            fingerprint=img_fp,
            cached=True,
            cache_status="hit",
            analysis_version=ANALYSIS_VERSION,
            community_flags=img_flags if img_flags >= 3 else None,
            community_notes=img_notes,
            vote_stats=VoteStats(**img_v_stats) if (img_v_stats["likes"] + img_v_stats["dislikes"]) > 0 else None,
            scans_remaining=_remaining_scans(subject_id),
        )

    _log_cache(http_request, "miss", img_fp, "no_fresh_versioned_image_entry")
    _enforce_analysis_burst(http_request, auth)
    rl = _check_rate_limit(subject_id)
    if rl:
        rl["request_id"] = _request_id(http_request)
        return JSONResponse(status_code=429, content=rl)
    try:
        image_data, media_type = await asyncio.wait_for(
            asyncio.to_thread(_fetch_and_resize_image, request.image_url),
            timeout=FACTCHECK_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        return ImageVerifyResponse(authenticity_score=50, verdict="uncertain", explanation="Image retrieval timed out. Please try again.", evidence=[])
    if not image_data:
        return ImageVerifyResponse(
            authenticity_score=50,
            verdict="uncertain",
            explanation="Could not fetch the image. It may be protected or too large.",
            evidence=[],
        )

    context_parts = []
    if request.social_context:
        sc = request.social_context
        if sc.get("platform"):
            context_parts.append(f"Platform: {sc['platform']}")
            context_parts.append(
                "This image is from a live post on the actual platform. "
                "If the image is a screenshot of text/UI, sharp rendering is normal. "
                "But ALWAYS check for AI tool watermarks/logos (Gemini, DALL-E, "
                "Midjourney, etc.) — those override everything and mean AI-generated."
            )
        if sc.get("username"):
            context_parts.append(f"Posted by: @{sc['username']}")
        if sc.get("post_text"):
            context_parts.append(f"Post text: {sc['post_text'][:500]}")
        if sc.get("timestamp"):
            context_parts.append(f"Posted: {sc['timestamp']}")
    if request.page_text:
        context_parts.append(f"Page text: {request.page_text[:500]}")

    context = "\n".join(context_parts) if context_parts else ""

    bottom_crop = _crop_bottom_edge(image_data)
    _reserve_llm_call()
    scans_remaining = _increment_and_get_remaining(subject_id)
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(get_image_verification, image_data, media_type, context, bottom_crop),
            timeout=IMAGE_ANALYSIS_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        logger.warning("Image provider timed out")
        return ImageVerifyResponse(
            authenticity_score=50, verdict="uncertain",
            explanation="Image analysis timed out. Please try again.", evidence=[],
            fingerprint=img_fp, cached=False, cache_status="miss",
            analysis_version=ANALYSIS_VERSION, scans_remaining=scans_remaining,
        )

    _AI_TOOL_EXACT = re.compile(
        r"dall[\-\s]?e|midjourney|stable.diffusion|adobe.firefly|"
        r"leonardo[\s.]ai|chatgpt|made.with.ai",
        re.IGNORECASE,
    )
    _AI_TOOL_CONTEXTUAL = re.compile(
        r"(?:gemini|sparkle|copilot).{0,20}(?:logo|icon|watermark|badge|ai\b)|"
        r"(?:logo|icon|watermark|badge).{0,20}(?:gemini|sparkle|copilot)",
        re.IGNORECASE,
    )
    combined_text = (result.get("explanation") or "") + " " + " ".join(result.get("evidence") or [])
    ai_detected = _AI_TOOL_EXACT.search(combined_text) or _AI_TOOL_CONTEXTUAL.search(combined_text)
    if ai_detected and result["verdict"] != "ai_generated":
        logger.info("AI tool indicator detected in LLM output: %s", ai_detected.group())
        result["authenticity_score"] = min(result["authenticity_score"], 20)
        result["verdict"] = "ai_generated"
        if "ai" not in (result.get("explanation") or "").lower():
            result["explanation"] += " AI tool watermark/logo detected in the image."

    claim_results = None
    caption = ""
    if request.social_context and request.social_context.get("post_text"):
        caption = request.social_context["post_text"]
    elif request.page_text:
        caption = request.page_text[:500]

    caption_tone = result.get("caption_tone", "informal")
    if caption and len(caption.strip()) >= 10 and caption_tone == "factual":
        try:
            fc = await asyncio.wait_for(
                asyncio.to_thread(_verify_image_claim, caption, request.page_url or ""),
                timeout=FACTCHECK_TIMEOUT_SECONDS,
            )
            if fc:
                claim_results = [FactCheckResult(**c) for c in fc]
        except Exception as exc:
            logger.warning("Image claim verification failed: %s", exc)
    elif caption and len(caption.strip()) >= 10 and caption_tone == "opinion_or_rhetorical":
        try:
            fc = await asyncio.wait_for(
                asyncio.to_thread(_verify_image_claim, caption, request.page_url or ""),
                timeout=FACTCHECK_TIMEOUT_SECONDS,
            )
            if fc:
                for c in fc:
                    c["status"] = "opinion"
                claim_results = [FactCheckResult(**c) for c in fc]
        except Exception as exc:
            logger.warning("Image claim verification failed: %s", exc)
        logger.info("Caption is opinion/rhetorical — claims tagged as opinion")
    elif caption and caption_tone == "informal":
        logger.info("Skipping claim verification — caption tone is informal")

    final_score = result["authenticity_score"]
    final_verdict = result["verdict"]
    final_explanation = result["explanation"]

    if claim_results:
        best_sc = 0
        best_corr = "not_corroborated"
        has_dispute = False
        has_verified = False
        source_names = []

        for cr in claim_results:
            if cr.status == "opinion":
                continue
            corr = cr.corroboration or "not_corroborated"
            sc = cr.source_count or 0

            if sc > best_sc:
                best_sc = sc
                best_corr = corr

            if cr.status == "disputed":
                has_dispute = True
            elif cr.status == "verified":
                has_verified = True

            if cr.related_articles:
                for a in cr.related_articles:
                    if a.source and a.source not in source_names:
                        source_names.append(a.source)

        image_is_fake = final_verdict in ("ai_generated", "manipulated")

        relevant_corr = best_corr in ("lightly_reported", "multiple_sources", "widely_reported")

        if not image_is_fake and relevant_corr:
            corr_boost = min(25, best_sc * 5)
            final_score = min(100, final_score + corr_boost)

            if has_verified:
                final_score = min(100, final_score + 15)

        if has_dispute:
            final_score = max(0, final_score - 25)

        if best_sc >= 2 and source_names and relevant_corr:
            names = ", ".join(source_names[:4])
            if image_is_fake:
                final_explanation += (
                    f" Note: the claimed event is real ({best_sc} news source(s) "
                    f"including {names}), but the image itself appears to be "
                    f"{'AI-generated' if final_verdict == 'ai_generated' else 'manipulated'}."
                )
            else:
                _negatives = re.compile(
                    r"(?:improbable|unverifiable|unsupported|unsubstantiated|"
                    r"no (?:clear |visible )?(?:indication|evidence|sign)|"
                    r"(?:not |un)(?:visib|confirm|verif))",
                    re.IGNORECASE,
                )
                if _negatives.search(final_explanation):
                    final_explanation = (
                        f"The claimed event is corroborated by {best_sc} news "
                        f"source(s) including {names}."
                    )
                else:
                    final_explanation += (
                        f" The claimed event is corroborated by "
                        f"{best_sc} news source(s) including {names}."
                    )

        if not image_is_fake:
            if final_score >= 55 and final_verdict in ("out_of_context", "uncertain"):
                final_verdict = "uncertain" if final_score < 65 else "authentic"
            elif final_score <= 25 and final_verdict == "uncertain":
                final_verdict = "manipulated"

    try:
        store_image_scan(request.image_url, {
            "authenticity_score": final_score,
            "verdict": final_verdict,
            "explanation": final_explanation,
            "evidence": result["evidence"],
            "claim_analysis": [c.model_dump() for c in claim_results] if claim_results else None,
        }, user_id=subject_id, analysis_version=ANALYSIS_VERSION,
           page_url=request.page_url, og_image=request.image_url)
    except Exception as exc:
        logger.warning("Image scan storage failed: %s", exc)

    _record_scan_access_async(img_fp, subject_id, "image")
    img_flags = get_flag_count(img_fp)
    img_notes_raw = get_community_notes(img_fp, limit=3)
    img_notes = [CommunityNote(**n) for n in img_notes_raw] if img_notes_raw else None
    img_v_stats = get_vote_stats(img_fp)
    return ImageVerifyResponse(
        authenticity_score=final_score,
        verdict=final_verdict,
        explanation=final_explanation,
        evidence=result["evidence"],
        claim_analysis=claim_results,
        fingerprint=img_fp,
        cached=False,
        cache_status="miss",
        analysis_version=ANALYSIS_VERSION,
        community_flags=img_flags if img_flags >= 3 else None,
        community_notes=img_notes,
        vote_stats=VoteStats(**img_v_stats) if (img_v_stats["likes"] + img_v_stats["dislikes"]) > 0 else None,
        scans_remaining=scans_remaining,
    )


_FLAG_VALIDATION_PROMPT = """\
You are a content moderation assistant. A user has flagged online content with the following justification.
Rate the quality of this flag on a scale of 0-100:
- 0-29: Low quality (vague, troll, spam, no real argument, just opinion with no substance)
- 30-69: Medium quality (has a point but lacks specifics or sources)
- 70-100: High quality (clear reasoning, specific claims, references evidence)

Respond with ONLY a JSON object: {"score": <number>, "reason": "<brief explanation>"}"""


def _validate_flag_quality(category: str, justification: str) -> tuple[int, str]:
    """Use a light LLM to score the quality of a community flag. Returns (score, reason)."""
    try:
        from llm_utils import _call_llm
        user_content = f"Category: {category}\nJustification: {justification}"
        raw = _call_llm(
            _FLAG_VALIDATION_PROMPT, user_content,
            min_tokens=100, model_override=FLAG_VALIDATION_MODEL,
        )
        match = re.search(r'\{[^}]+\}', raw)
        if match:
            data = json.loads(match.group())
            return int(data.get("score", 50)), data.get("reason", "")
    except Exception as exc:
        logger.warning("Flag validation LLM failed, defaulting to 50: %s", exc)
    return 50, ""


@app.post("/flag", response_model=FlagResponse)
@_limit_analysis_capacity
async def flag_content(request: FlagRequest, http_request: Request):
    """Add a community note (flag with justification), validated by LLM."""
    auth = _require_session(http_request)
    _enforce_analysis_burst(http_request, auth)
    subject_id = auth.subject_id
    if request.category not in VALID_FLAG_CATEGORIES:
        return FlagResponse(success=False, flag_count=get_flag_count(request.fingerprint))
    if not request.justification or len(request.justification.strip()) < 30:
        return FlagResponse(success=False, flag_count=get_flag_count(request.fingerprint))

    if has_user_flagged(request.fingerprint, subject_id):
        count = get_flag_count(request.fingerprint)
        return FlagResponse(success=True, flag_count=count, already_flagged=True)

    _reserve_llm_call()
    try:
        quality_score, rejection_reason = await asyncio.wait_for(
            asyncio.to_thread(_validate_flag_quality, request.category, request.justification),
            timeout=ANALYSIS_TIMEOUT_SECONDS,
        )
    except TimeoutError as exc:
        raise HTTPException(status_code=503, detail={"error": "provider_timeout", "message": "Flag validation timed out; please retry"}, headers={"Retry-After": "3"}) from exc
    if quality_score < 30:
        return FlagResponse(
            success=False,
            flag_count=get_flag_count(request.fingerprint),
            rejection_reason=rejection_reason or "Please provide a more specific and substantive justification.",
        )

    note_dict = add_community_flag(
        request.fingerprint, subject_id,
        request.category, request.justification,
        request.source_urls, quality_score=quality_score,
    )
    count = get_flag_count(request.fingerprint)


    return FlagResponse(
        success=note_dict is not None,
        flag_count=count,
        note=CommunityNote(**note_dict) if note_dict else None,
    )


@app.post("/vote", response_model=VoteResponse)
async def vote_on_result(request: VoteRequest, http_request: Request):
    """Like (+1) or dislike (-1) an analysis result."""
    subject_id = _require_session(http_request).subject_id
    if request.vote not in (1, -1):
        return VoteResponse(success=False)
    stored = store_vote(request.fingerprint, subject_id, request.vote)
    stats = get_vote_stats(request.fingerprint)
    return VoteResponse(success=stored, likes=stats["likes"], dislikes=stats["dislikes"])


@app.get("/community-notes/{fingerprint}")
async def fetch_community_notes(fingerprint: str, request: Request):
    """Fetch community notes and vote stats for a fingerprint."""
    _require_session(request)
    notes = get_community_notes(fingerprint)
    stats = get_vote_stats(fingerprint)
    count = get_flag_count(fingerprint)
    return {
        "notes": [CommunityNote(**n) for n in notes],
        "vote_stats": VoteStats(**stats),
        "flag_count": count,
    }


@app.post("/analyze")
@_limit_analysis_capacity
async def analyze_page(request: AnalyzeRequest, http_request: Request):
    """Unified endpoint for the browser extension."""
    auth = _require_session(http_request)
    subject_id = auth.subject_id

    meta_dict = request.metadata.model_dump() if request.metadata else {}
    pre_classification_data = classify_page_content(
        title=request.title,
        text=request.text,
        url=request.url,
        metadata=meta_dict,
    )
    pre_classification = ContentClassification(**pre_classification_data)

    # Cache identity excludes common dynamic boilerplate and includes the
    # analysis version so prompt/model changes never reuse stale results.
    canonical_cache_url = normalize_url(
        request.metadata.canonical_url
        if request.metadata and request.metadata.canonical_url
        else request.url
    )
    content_signature = compute_content_signature(request.text)
    fingerprint = compute_analysis_fingerprint(
        request.text,
        url=canonical_cache_url,
        title=request.title,
        analysis_version=ANALYSIS_VERSION,
    )

    # Build domain profile (visible to the user).
    domain_prof = None
    if request.url:
        base_domain = extract_base_domain(request.url)
        if base_domain:
            is_rep = base_domain in REPUTABLE_DOMAINS
            prof_data = get_domain_profile(base_domain, is_reputable=is_rep)
            if prof_data:
                domain_prof = DomainProfile(**prof_data)

    if fingerprint:
        cached = find_cached_scan(
            fingerprint, ANALYSIS_VERSION, ANALYSIS_CACHE_MAX_AGE_HOURS
        )
        cache_reason = "fresh_versioned_entry"
        if not cached and canonical_cache_url and content_signature:
            cached = find_cached_scan_by_url(
                canonical_cache_url, ANALYSIS_VERSION, content_signature,
                ANALYSIS_CACHE_MAX_AGE_HOURS,
            )
            if cached and cached.get("fingerprint"):
                # Claims, shares, votes and scan-access counts must continue to
                # reference the stored analysis identity on a near-duplicate hit.
                fingerprint = cached["fingerprint"]
                cache_reason = "same_url_similar_content"
        if cached:
            _enforce_cache_hit_limit(subject_id)
            _log_cache(http_request, "hit", fingerprint, cache_reason)
            _record_scan_access_async(fingerprint, subject_id, "page")
            fc_response = None
            if cached.get("judgement"):
                try:
                    fc_data = json.loads(cached["judgement"])
                    fc_response = [FactCheckResult(**fc) for fc in fc_data]
                except (json.JSONDecodeError, TypeError):
                    pass

            comm_flags = get_flag_count(fingerprint)
            comm_scans = count_scans_for_fingerprint(fingerprint)
            notes_raw = get_community_notes(fingerprint, limit=3)
            notes = [CommunityNote(**n) for n in notes_raw] if notes_raw else None
            v_stats = get_vote_stats(fingerprint)
            cached_source = SourceInfo(**cached["source_info"]) if cached.get("source_info") else None
            cached_classification = ContentClassification(
                **(cached.get("content_classification") or pre_classification_data)
            )
            cached_source_quality = (
                V1SourceQualityAssessment(**cached["source_quality"])
                if cached.get("source_quality") else None
            )

            return AnalyzeResponse(
                trust_score=cached.get("trust_score", 50),
                verdict=cached.get("verdict", "suspicious"),
                explanation=cached.get("explanation", ""),
                evidence=cached.get("evidence", []),
                cached=True,
                cache_status="hit",
                analysis_version=ANALYSIS_VERSION,
                fact_checks=fc_response,
                source_info=cached_source,
                domain_profile=domain_prof,
                community_flags=comm_flags if comm_flags >= 3 else None,
                community_scans=comm_scans if comm_scans > 1 else None,
                community_notes=notes,
                vote_stats=VoteStats(**v_stats) if (v_stats["likes"] + v_stats["dislikes"]) > 0 else None,
                fingerprint=fingerprint,
                scans_remaining=_remaining_scans(subject_id),
                content_classification=cached_classification,
                source_quality=cached_source_quality,
            )
        _log_cache(http_request, "miss", fingerprint, "no_exact_or_similar_entry")
    else:
        _log_cache(http_request, "bypass", None, "content_not_cacheable")
    _enforce_analysis_burst(http_request, auth)
    # ── Build the LLM prompt with metadata + video context ────────────
    content_parts = []

    header_parts = []
    if request.url:
        header_parts.append(f"URL: {request.url}")
    if request.title:
        header_parts.append(f"Title: {request.title}")
    if request.metadata:
        m = request.metadata
        if m.site_name:
            header_parts.append(f"Site: {m.site_name}")
        if m.author:
            header_parts.append(f"Author: {m.author}")
        if m.publish_date:
            header_parts.append(f"Published: {m.publish_date}")
        if m.og_type:
            header_parts.append(f"Page type: {m.og_type}")

    if header_parts:
        content_parts.append("Page metadata:\n" + "\n".join(header_parts))

    # Video context
    if request.video_info:
        v = request.video_info
        video_parts = [f"Video detected (platform: {v.platform or 'unknown'})"]
        if v.title:
            video_parts.append(f"Video title: {v.title}")
        if v.channel:
            video_parts.append(f"Channel: {v.channel}")
        if v.description:
            video_parts.append(f"Description: {v.description[:500]}")
        if v.ai_platform:
            video_parts.append(f"AI video platform detected: {v.platform_name}")
        content_parts.append("Video info:\n" + "\n".join(video_parts))

    if request.text:
        content_parts.append(f"Page content:\n{request.text[:3000]}")

    if request.links:
        links_summary = "\n".join(request.links[:10])
        content_parts.append(f"Links found:\n{links_summary}")

    combined = "\n\n---\n\n".join(content_parts)

    if not combined.strip():
        return AnalyzeResponse(
            trust_score=50,
            verdict="unknown",
            explanation="No content was provided for analysis.",
            evidence=["No text, links, or images were extracted from the page."],
            cache_status="bypass",
            analysis_version=ANALYSIS_VERSION,
            scans_remaining=_remaining_scans(subject_id),
            content_classification=pre_classification,
        )

    # Anonymous community reports and helpfulness votes are retained for
    # moderation/product feedback only; they never enter provider prompts.
    kb_hits = []
    # ── Run LLM analysis + fact-checking in parallel ────────────────────
    llm_result = None
    fact_checks = []
    claims_pending = False
    claims_completed = False

    inflight_key = fingerprint or f"uncacheable:{_request_id(http_request)}"
    inflight_ready, owns_provider_start = _claim_page_analysis(inflight_key)
    if owns_provider_start:
        rl = _check_rate_limit(subject_id)
        if rl:
            rl["request_id"] = _request_id(http_request)
            _fail_page_analysis(inflight_key, inflight_ready, RuntimeError("quota_rejected"))
            return JSONResponse(status_code=429, content=rl)
        try:
            # Reserve global budget first; charge the installation only when
            # provider work is actually about to begin.
            _reserve_llm_call()
            scans_remaining = _increment_and_get_remaining(subject_id)
            llm_future = _bg_pool.submit(get_structured_analysis, combined)
            fc_future = None
            if factcheck_available() and request.text:
                fc_future = _bg_pool.submit(
                    _verify_claims, request.text, request.title or "", request.url or ""
                )
            _publish_page_analysis(
                inflight_key, inflight_ready, llm_future, fc_future
            )
            result_cache_status = "miss"
        except Exception as exc:
            _fail_page_analysis(inflight_key, inflight_ready, exc)
            raise
    else:
        logger.info(json.dumps({
            "event": "analysis_coalesced",
            "request_id": _request_id(http_request),
            "fingerprint": fingerprint[:16] if fingerprint else None,
            "analysis_version": ANALYSIS_VERSION,
        }, separators=(",", ":")))
        scans_remaining = _remaining_scans(subject_id)
        result_cache_status = "coalesced"
        try:
            llm_future, fc_future = await asyncio.wait_for(
                asyncio.wrap_future(inflight_ready),
                timeout=ANALYSIS_TIMEOUT_SECONDS,
            )
        except TimeoutError as exc:
            raise HTTPException(
                status_code=503,
                detail={"error": "provider_timeout", "message": "Analysis startup timed out; please retry"},
                headers={"Retry-After": "3"},
            ) from exc

    try:
        llm_result = await asyncio.wait_for(
            asyncio.wrap_future(llm_future), timeout=ANALYSIS_TIMEOUT_SECONDS
        )
    except TimeoutError:
        logger.warning("Article provider timed out")
        if fc_future:
            fc_future.cancel()
        _finish_page_analysis(inflight_key, inflight_ready)
        return AnalyzeResponse(
            trust_score=50,
            verdict="unknown",
            explanation="Analysis timed out. Please try again.",
            evidence=[],
            cached=False,
            fingerprint=fingerprint,
            cache_status=result_cache_status,
            analysis_version=ANALYSIS_VERSION,
            scans_remaining=scans_remaining,
            content_classification=pre_classification,
        )
    except Exception:
        _finish_page_analysis(inflight_key, inflight_ready)
        raise

    if fc_future is not None:
        if fc_future.done():
            try:
                fact_checks = fc_future.result()
                claims_completed = True
            except Exception as exc:
                logger.warning("Fact-check pipeline failed: %s", exc)
        else:
            claims_pending = True
            def _on_claims_done(future: Future, fp=fingerprint):
                try:
                    claims = future.result()
                    if fp:
                        update_scan_claims(fp, json.dumps(claims or []))
                except Exception as exc:
                    logger.warning("Background claims storage failed: %s", exc)
            fc_future.add_done_callback(_on_claims_done)

    # ── Run structural scoring ────────────────────────────────────────
    classification_data = classify_page_content(
        title=request.title,
        text=request.text,
        url=request.url,
        metadata=meta_dict,
        llm_result=llm_result,
        claims_completed=claims_completed,
        fact_checks=fact_checks,
    )
    content_classification = ContentClassification(**classification_data)

    structural_score, signals = compute_structural_score(
        url=request.url,
        title=request.title,
        text=request.text,
        links=request.links,
        metadata=meta_dict,
    )

    # ── Domain trust graph signal ─────────────────────────────────────
    if request.url:
        domain_signal = compute_domain_trust_signal(request.url)
        if domain_signal:
            signals.append(domain_signal)

    # ── AI video platform signal ──────────────────────────────────────
    if request.video_info and request.video_info.ai_platform:
        signals.append({
            "name": "ai_video_platform",
            "delta": -20,
            "detail": f"Content is from AI video platform: {request.video_info.platform_name}",
        })
        structural_score = max(0, min(100, structural_score - 20))

    # Claim evidence is represented separately in v1 and never changes the
    # source-quality score used for legacy compatibility.
    llm_score = llm_result.get("trust_score", 50)
    source_quality_score = max(
        0, min(100, int(LLM_WEIGHT * llm_score + STRUCTURAL_WEIGHT * structural_score))
    )
    source_quality = _build_source_quality_assessment(source_quality_score, signals)
    combined_score = source_quality_score
    combined_score, safe_verdict, safe_explanation = apply_factual_verdict_safeguard(
        combined_score,
        llm_result.get("verdict", "suspicious"),
        llm_result.get("explanation", ""),
        classification_data,
        fact_checks,
    )
    llm_result = {
        **llm_result,
        "verdict": safe_verdict,
        "explanation": safe_explanation,
    }

    all_evidence = list(llm_result.get("evidence", []))


    for fc in fact_checks:
        if fc.get("status") == "disputed" and fc.get("source"):
            all_evidence.append(
                f"Claim disputed by {fc['source']}: \"{fc['claim'][:60]}\""
            )

    # ── Build source info ─────────────────────────────────────────────
    source_info = None
    if request.metadata or request.url:
        from urllib.parse import urlparse
        domain = None
        if request.url:
            try:
                domain = urlparse(request.url).netloc
            except Exception:
                pass
        source_info = SourceInfo(
            site_name=request.metadata.site_name if request.metadata else None,
            author=request.metadata.author if request.metadata else None,
            publish_date=request.metadata.publish_date if request.metadata else None,
            domain=domain,
        )

    # ── Store result + update domain graph ────────────────────────────
    result_dict = {
        "trust_score": combined_score,
        "verdict": llm_result.get("verdict", "suspicious"),
        "explanation": llm_result.get("explanation", ""),
        "evidence": all_evidence,
        "judgement": json.dumps(fact_checks) if claims_completed else None,
    }
    try:
        canonical_url = normalize_url(
            request.metadata.canonical_url if request.metadata and request.metadata.canonical_url else request.url
        )
        og_image = normalize_url(request.metadata.og_image) if request.metadata else ""
        store_analysis_result(
            "page_scan", combined[:500], result_dict,
            fingerprint=fingerprint, url=request.url,
            user_id=subject_id, analysis_version=ANALYSIS_VERSION,
            scanned_title=request.title, canonical_url=canonical_url,
            source_info=source_info.model_dump() if source_info else None,
            og_image=og_image, content_signature=content_signature,
            content_classification=classification_data,
            source_quality=source_quality.model_dump(),
        )
    except Exception as exc:
        logger.warning("Storage failed: %s", exc)

    if request.url and classification_data.get("factual_verdict_allowed"):
        try:
            update_domain_stats(request.url, combined_score, llm_result.get("verdict", "suspicious"))
        except Exception as exc:
            logger.warning("Domain stats update failed: %s", exc)

    _record_scan_access_async(fingerprint, subject_id, "page")

    fc_response = [FactCheckResult(**fc) for fc in fact_checks] if claims_completed else None

    comm_flags = get_flag_count(fingerprint) if fingerprint else 0
    comm_scans = count_scans_for_fingerprint(fingerprint) if fingerprint else 0
    notes_raw = get_community_notes(fingerprint, limit=3) if fingerprint else []
    notes = [CommunityNote(**n) for n in notes_raw] if notes_raw else None
    v_stats = get_vote_stats(fingerprint) if fingerprint else {"likes": 0, "dislikes": 0}

    kb_response = None
    if kb_hits:
        kb_response = [{
            "counter_claim": h["counter_claim"],
            "category": h.get("category"),
            "confidence": h.get("confidence"),
            "sources": h.get("sources", []),
        } for h in kb_hits]

    _finish_page_analysis(inflight_key, inflight_ready)
    return AnalyzeResponse(
        trust_score=combined_score,
        verdict=llm_result.get("verdict", "suspicious"),
        explanation=llm_result.get("explanation", ""),
        evidence=all_evidence,
        source_info=source_info,
        domain_profile=domain_prof,
        structural_signals=signals,
        fact_checks=fc_response if not claims_pending else None,
        cached=False,
        cache_status=result_cache_status,
        analysis_version=ANALYSIS_VERSION,
        community_flags=comm_flags if comm_flags >= 3 else None,
        community_scans=comm_scans if comm_scans > 1 else None,
        community_notes=notes,
        vote_stats=VoteStats(**v_stats) if (v_stats["likes"] + v_stats["dislikes"]) > 0 else None,
        kb_matches=kb_response,
        fingerprint=fingerprint,
        claims_pending=claims_pending if claims_pending else None,
        scans_remaining=scans_remaining,
        content_classification=content_classification,
        source_quality=source_quality,
    )


@app.post("/v1/analyze", response_model=V1AnalyzeResponse)
async def analyze_page_v1(request: AnalyzeRequest, http_request: Request):
    """Return the additive v1 evidence contract while preserving legacy fields."""
    legacy = await analyze_page(request, http_request)
    if not isinstance(legacy, AnalyzeResponse):
        return legacy
    return _to_v1_analysis(legacy, _request_id(http_request))


@app.get("/v1/analyses/{analysis_id}/claims", response_model=V1ClaimsResponse)
async def get_v1_claims(
    request: Request,
    analysis_id: Annotated[str, ApiPath(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9:_-]+$")],
):
    """Poll normalized claim processing state for a v1 analysis."""
    _require_session(request)
    raw = get_scan_claims(analysis_id)
    if raw is None:
        return V1ClaimsResponse(
            analysis_id=analysis_id,
            processing_state="processing",
            limitations=["Claim-level evidence is still being processed."],
        )
    try:
        parsed = json.loads(raw)
        fact_checks = [FactCheckResult(**item) for item in parsed]
    except (json.JSONDecodeError, TypeError, ValueError):
        return V1ClaimsResponse(
            analysis_id=analysis_id,
            processing_state="failed",
            limitations=["Stored claim results could not be read. Retry the analysis."],
        )
    limitations = []
    if not fact_checks:
        limitations.append("No checkable claims were identified in the extracted content.")
    return V1ClaimsResponse(
        analysis_id=analysis_id,
        processing_state="complete",
        claims=[_map_v1_claim(item) for item in fact_checks],
        limitations=limitations,
    )

@app.get("/claims/{fingerprint}")
async def get_claims(fingerprint: str, request: Request):
    """Fetch claim analysis for a previously scanned page (used for progressive loading)."""
    _require_session(request)
    raw = get_scan_claims(fingerprint)
    if raw:
        try:
            claims = json.loads(raw)
            fc_response = [FactCheckResult(**fc) for fc in claims]
            return {"pending": False, "fact_checks": fc_response}
        except (json.JSONDecodeError, TypeError):
            pass
    return {"pending": True, "fact_checks": None}


class ShareRequest(BaseModel):
    fingerprint: str = Field(min_length=16, max_length=128)


@app.post("/share")
async def create_share(request: ShareRequest, http_request: Request):
    """Create a share only from a result already stored by FactScope."""
    auth_context = _require_session(http_request)
    fingerprint = request.fingerprint
    if fingerprint.startswith("img:"):
        stored = find_image_scan_by_fingerprint(fingerprint)
        if not stored:
            raise HTTPException(status_code=404, detail="Stored analysis not found")
        scanned_url = stored.get("page_url", "") or stored.get("image_url", "")
        data = {
            "result_type": "image",
            "score": stored.get("authenticity_score", 50),
            "verdict": stored.get("verdict", "uncertain"),
            "explanation": stored.get("explanation", ""),
            "evidence": stored.get("evidence", []),
            "scanned_url": scanned_url,
            "scanned_title": stored.get("scanned_title", ""),
            "og_image": stored.get("og_image", "") or stored.get("image_url", ""),
            "fingerprint": fingerprint,
        }
    else:
        stored = find_by_fingerprint(fingerprint)
        if not stored:
            raise HTTPException(status_code=404, detail="Stored analysis not found")
        scanned_url = stored.get("canonical_url", "") or stored.get("url", "") or ""
        from urllib.parse import urlsplit
        try:
            domain = urlsplit(scanned_url).hostname or ""
        except ValueError:
            domain = ""
        data = {
            "result_type": "page",
            "score": stored.get("trust_score", 50),
            "verdict": stored.get("verdict", "uncertain"),
            "explanation": stored.get("explanation", ""),
            "evidence": stored.get("evidence", []),
            "domain": domain,
            "source_info": stored.get("source_info"),
            "scanned_url": scanned_url,
            "scanned_title": stored.get("scanned_title", ""),
            "og_image": stored.get("og_image", ""),
            "fingerprint": fingerprint,
        }
    data["owner_subject_id"] = auth_context.subject_id
    share_id = store_shared_result(data)
    base = "http://localhost:8000" if ENVIRONMENT == "development" else "https://factscope-api.onrender.com"
    return {"share_url": f"{base}/s/{share_id}", "share_id": share_id}


_SHARE_TEMPLATE = (Path(__file__).parent / "templates" / "share.html").read_text(encoding="utf-8")


def _render_share_page(data: dict, share_url: str = "") -> str:
    import html as _html
    import math
    from urllib.parse import quote

    def _safe_http_url(value: object) -> str:
        from urllib.parse import urlsplit
        raw = str(value or "")
        try:
            parsed = urlsplit(raw)
        except ValueError:
            return ""
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        if parsed.username or parsed.password:
            return ""
        return raw

    try:
        score = max(0, min(100, int(data.get("score", 50))))
    except (TypeError, ValueError):
        score = 50
    verdict = str(data.get("verdict", "uncertain"))[:50]
    result_type = "image" if data.get("result_type") == "image" else "page"

    is_image = result_type == "image"
    score_label = "authenticity score" if is_image else "trust score"
    type_label = "Image Verification" if is_image else "Content Analysis"

    verdict_map = {
        "authentic": ("Authentic", "\u2705"),
        "likely_authentic": ("Likely Authentic", "\u2705"),
        "uncertain": ("Uncertain", "\u2753"),
        "suspicious": ("Suspicious", "\u26A0\uFE0F"),
        "ai_generated": ("AI Generated", "\U0001F916"),
        "likely_ai_generated": ("Likely AI-Generated", "\U0001F916"),
        "possibly_manipulated": ("Possibly Manipulated", "\u26A0\uFE0F"),
        "manipulated": ("Manipulated", "\u26A0\uFE0F"),
        "phishing": ("Phishing Alert", "\U0001F6A8"),
    }
    verdict_label, verdict_icon = verdict_map.get(verdict, (_html.escape(verdict.replace("_", " ").title()), "\u2753"))
    color = "#22c55e" if score >= 70 else "#f59e0b" if score >= 40 else "#ef4444"

    # Full-circle gauge geometry (SVG circle r=78, circumference = 2*pi*78)
    circumference = 2 * math.pi * 78  # ~490.1
    dash_offset = circumference * (1 - score / 100)

    domain = _html.escape(str(data.get("domain", "") or "")[:253], quote=True)
    scanned_url = _safe_http_url(data.get("scanned_url", ""))
    scanned_title = _html.escape(data.get("scanned_title", "") or "")
    og_image = _safe_http_url(data.get("og_image", ""))

    # OG image: use article's own image for rich social previews
    if og_image:
        og_image_meta = (
            f'<meta property="og:image" content="{_html.escape(og_image, quote=True)}">'
            f'\n<meta name="twitter:image" content="{_html.escape(og_image, quote=True)}">'
        )
    else:
        og_image_meta = ""

    # Build the left-column preview HTML
    preview_label = "Image scanned on" if is_image else "Page scanned"
    favicon_url = f"https://www.google.com/s2/favicons?domain={domain}&sz=32" if domain else ""

    if og_image:
        image_block = f'<img class="preview-image" src="{_html.escape(og_image, quote=True)}" alt="Article preview" onerror="this.style.display=\'none\';document.querySelector(\'.main\').classList.add(\'no-preview-image\')">'
    else:
        image_block = ""

    source_line = ""
    if domain:
        fav = f'<img class="preview-favicon" src="{favicon_url}" alt="" onerror="this.style.display=\'none\'">' if favicon_url else ""
        source_line = f'<div class="preview-source">{fav}<span class="preview-domain">{domain}</span></div>'

    url_line = ""
    if scanned_url:
        url_line = f'<a class="preview-url" href="{_html.escape(scanned_url)}" target="_blank" rel="noopener">{_html.escape(scanned_url[:100])}</a>'

    title_block = f'<div class="preview-title">{scanned_title}</div>' if scanned_title else ""

    if scanned_title or scanned_url or og_image:
        preview_html = (
            f'<div class="preview">'
            f'{image_block}'
            f'<div class="preview-body">'
            f'<div class="preview-label">{preview_label}</div>'
            f'{title_block}{source_line}{url_line}'
            f'</div></div>'
        )
    else:
        preview_html = (
            '<div class="preview"><div class="preview-placeholder">'
            '<div class="placeholder-icon"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.4"><path d="M9 12h6M12 9v6M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg></div>'
            '<div style="color:var(--text-muted);font-size:13px">Content preview unavailable</div>'
            '</div></div>'
        )

    explanation = _html.escape(data.get("explanation", "") or "")
    explanation_short = explanation[:160] + "\u2026" if len(explanation) > 160 else explanation

    evidence = data.get("evidence", []) or []
    evidence_items = "".join(f"<li>{_html.escape(str(e))}</li>" for e in evidence[:5])
    evidence_html = (
        f'<div class="analysis-card"><div class="analysis-heading">'
        f'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h10"/></svg>'
        f'Key findings</div><ul class="evidence-list">{evidence_items}</ul></div>'
        if evidence_items else ""
    )

    # Platform share buttons — conversational tone
    emoji = "\u2705" if score >= 70 else "\u26A0\uFE0F" if score >= 40 else "\U0001F6A8"
    source_bit = f" from {domain}" if domain else ""
    share_text = f"{emoji} I just ran this{source_bit} through FactScope \u2014 scored {score}% ({verdict_label}). See the full breakdown:"
    encoded_text = quote(share_text)
    encoded_url = quote(share_url)
    full_msg = quote(f"{share_text}\n{share_url}")

    x_svg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>'
    wa_svg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>'
    tg_svg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M11.944 0A12 12 0 000 12a12 12 0 0012 12 12 12 0 0012-12A12 12 0 0012 0a12 12 0 00-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 01.171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.479.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/></svg>'

    share_buttons_html = (
        '<div class="share-section"><div class="share-bar">'
        '<span class="share-label">Share this result</span>'
        f'<a class="share-btn twitter" href="https://twitter.com/intent/tweet?text={encoded_text}&url={encoded_url}" target="_blank" rel="noopener">{x_svg} Twitter</a>'
        f'<a class="share-btn whatsapp" href="https://api.whatsapp.com/send?text={full_msg}" target="_blank" rel="noopener">{wa_svg} WhatsApp</a>'
        f'<a class="share-btn telegram" href="https://t.me/share/url?url={encoded_url}&text={encoded_text}" target="_blank" rel="noopener">{tg_svg} Telegram</a>'
        f'<button class="share-btn copy" onclick="navigator.clipboard.writeText(\'{_html.escape(share_url)}\').then(()=>this.textContent=\'Copied!\')">&#128279; Copy link</button>'
        '</div></div>'
    ) if share_url else ""

    return _SHARE_TEMPLATE.format(
        score=score,
        score_label=score_label,
        type_label=type_label,
        verdict_label=verdict_label,
        verdict_icon=verdict_icon,
        color=color,
        circumference=f"{circumference:.1f}",
        dash_offset=f"{dash_offset:.1f}",
        domain=domain,
        og_image_meta=og_image_meta,
        preview_html=preview_html,
        layout_class="" if og_image else "no-preview-image",
        explanation=explanation,
        explanation_short=explanation_short,
        evidence_html=evidence_html,
        share_buttons_html=share_buttons_html,
    )


@app.get("/s/{share_id}", response_class=HTMLResponse)
async def view_shared_result(share_id: str):
    """Serve a read-only HTML page for a shared result."""
    from config import ENVIRONMENT
    data = get_shared_result(share_id)
    if not data:
        return HTMLResponse(
            "<html><body style='font-family:sans-serif;text-align:center;padding:60px'>"
            "<h2>Result not found</h2><p>This shared link may have expired or does not exist.</p></body></html>",
            status_code=404,
        )
    base = "http://localhost:8000" if ENVIRONMENT == "development" else "https://factscope-api.onrender.com"
    share_url = f"{base}/s/{share_id}"
    return HTMLResponse(_render_share_page(data, share_url=share_url))




@app.get("/health")
async def health():
    return {"status": "ok", "version": app.version}


@app.get("/debug/db-status")
async def db_status():
    """Check database connectivity and row counts."""
    from db import _get_conn, _use_turso
    try:
        conn = _get_conn()
        scans = conn.execute("SELECT COUNT(*) as cnt FROM scans").fetchone()
        images = conn.execute("SELECT COUNT(*) as cnt FROM image_scans").fetchone()
        flags = conn.execute("SELECT COUNT(*) as cnt FROM community_flags").fetchone()
        latest = conn.execute(
            "SELECT fingerprint, trust_score, timestamp FROM scans ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()
        return {
            "turso": _use_turso,
            "scans_count": scans[0] if scans else 0,
            "image_scans_count": images[0] if images else 0,
            "flags_count": flags[0] if flags else 0,
            "latest_scan": dict(latest) if latest else None,
        }
    except Exception as exc:
        return {"error": str(exc)}


@app.get("/debug/find/{fp}")
async def debug_find(fp: str):
    """Test fingerprint lookup directly."""
    from db import _get_conn
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT fingerprint, trust_score, verdict FROM scans WHERE fingerprint = ?",
            (fp,),
        ).fetchone()
        all_fps = conn.execute(
            "SELECT fingerprint FROM scans ORDER BY timestamp DESC LIMIT 5"
        ).fetchall()
        return {
            "query_hit": row is not None,
            "result": dict(row) if row else None,
            "stored_fingerprints": [dict(r)["fingerprint"][:20] for r in all_fps],
        }
    except Exception as exc:
        return {"error": str(exc)}


# ═══════════════════════════════════════════════════════════════════════════════
# Rate-limit / Usage endpoints
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/user/usage")
async def user_usage(request: Request, user_id: str = ""):
    del user_id
    uid = _require_session(request).subject_id
    tier = get_user_tier(uid)
    limit = SCAN_LIMITS.get(tier, SCAN_LIMITS["free"])
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    used = get_daily_scan_count(uid, today)
    tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    ).isoformat()
    is_admin = uid in ADMIN_USER_IDS
    return {
        "tier": tier,
        "limit": limit,
        "used": used,
        "remaining": max(0, limit - used) if not is_admin else 999,
        "resets_at": tomorrow,
        "admin": is_admin,
    }


class RedeemRequest(BaseModel):
    user_id: Optional[str] = None
    key: str


@app.post("/redeem-key")
async def redeem_key(req: RedeemRequest, request: Request):
    subject_id = _require_session(request).subject_id
    new_tier = redeem_license_key(subject_id, req.key)
    if not new_tier:
        return JSONResponse(status_code=400, content={
            "error": "invalid_key",
            "message": "This license key is invalid or has already been used.",
        })
    limit = SCAN_LIMITS.get(new_tier, SCAN_LIMITS["free"])
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    used = get_daily_scan_count(subject_id, today)
    return {
        "success": True,
        "tier": new_tier,
        "limit": limit,
        "remaining": max(0, limit - used),
    }



_retention_task = None


async def _retention_cleanup_loop():
    while True:
        try:
            deleted = await asyncio.to_thread(
                purge_expired_data,
                RAW_SCAN_RETENTION_DAYS,
                TELEMETRY_RETENTION_DAYS,
            )
            logger.info(json.dumps({"event": "retention_cleanup", "deleted": deleted}, separators=(",", ":")))
        except Exception as exc:
            logger.error("Retention cleanup failed: %s", type(exc).__name__)
        await asyncio.sleep(max(60, RETENTION_CLEANUP_INTERVAL_SECONDS))


@app.on_event("startup")
async def start_retention_cleanup():
    global _retention_task
    if _retention_task is None or _retention_task.done():
        _retention_task = asyncio.create_task(_retention_cleanup_loop())


@app.on_event("shutdown")
async def stop_retention_cleanup():
    global _retention_task
    if _retention_task is None:
        return
    _retention_task.cancel()
    try:
        await _retention_task
    except asyncio.CancelledError:
        pass
    _retention_task = None
if ENVIRONMENT == "production":
    _DEVELOPMENT_ONLY_PATHS = {
        "/debug/db-status",
        "/debug/find/{fp}",
    }
    app.router.routes = [
        route for route in app.router.routes
        if getattr(route, "path", None) not in _DEVELOPMENT_ONLY_PATHS
    ]


if __name__ == "__main__":
    from config import PORT, ENVIRONMENT
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        reload=(ENVIRONMENT == "development"),
    )
