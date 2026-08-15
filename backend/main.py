import asyncio
from concurrent.futures import ThreadPoolExecutor, Future
from functools import wraps
from threading import Lock

from fastapi import FastAPI, Path as ApiPath, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from typing import Annotated, Optional, Literal
from elastic_utils import store_analysis_result, find_by_fingerprint, get_domain_profile
from db import (store_image_scan, find_image_scan, find_image_scan_by_fingerprint, find_cached_scan, find_cached_scan_by_url, add_community_flag,
                get_flag_count, has_user_flagged, count_scans_for_fingerprint, record_scan_access,
                update_scan_claims, get_scan_claims, url_hash,
                get_community_notes, store_vote, get_vote_stats,
                VALID_FLAG_CATEGORIES,
                store_shared_result, get_shared_result, update_shared_card, get_shared_card,
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
    version="0.20.0",
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
    relevance_score: Optional[float] = None
    published_at: Optional[str] = None
    recency: Optional[Literal["current", "recent", "older", "unknown"]] = None
    reachable: Optional[bool] = None
    independent: Optional[bool] = None
    semantic_relevance: Optional[float] = None
    stance: Optional[Literal["corroborating", "contradicting", "contextual", "low_relevance", "unavailable"]] = None
    source_type: Optional[Literal["primary", "secondary"]] = None
    evidence_level: Optional[Literal["direct_factcheck", "corroborating", "matching_coverage", "related_context", "broader_context"]] = None
    discovery_basis: Optional[Literal["strong_match", "topic_overlap", "repeated_report", "full_text_context"]] = None
    additional_reports: int = 0
    repeated_by: list[str] = Field(default_factory=list)


class FactCheckResult(BaseModel):
    claim: str
    status: str
    source: Optional[str] = None
    source_url: Optional[str] = None
    rating: Optional[str] = None
    source_count: Optional[int] = None
    corroboration: Optional[str] = None
    average_relevance: Optional[float] = None
    source_reachable: Optional[bool] = None
    related_articles: Optional[list[RelatedArticle]] = None
    rejected_articles: Optional[list[dict]] = None
    validation_summary: Optional[dict] = None
    evidence_status: Optional[Literal["corroborated_reporting", "contradicted_reporting", "mixed_reporting", "insufficient"]] = None
    corroborating_source_count: Optional[int] = None
    contradicting_source_count: Optional[int] = None
    primary_source_count: Optional[int] = None
    matching_coverage_count: Optional[int] = None
    context_count: Optional[int] = None
    context_articles: Optional[list[RelatedArticle]] = None
    reviewed_claim: Optional[str] = None
    claim_match_score: Optional[float] = None
    factcheck_match: Optional[Literal["strong", "related"]] = None


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
    relevance_score: Optional[float] = None
    published_at: Optional[str] = None
    recency: Optional[Literal["current", "recent", "older", "unknown"]] = None
    reachable: Optional[bool] = None
    independent: Optional[bool] = None
    semantic_relevance: Optional[float] = None
    stance: Optional[Literal["corroborating", "contradicting", "contextual", "low_relevance", "unavailable"]] = None
    source_type: Optional[Literal["primary", "secondary"]] = None
    evidence_level: Optional[Literal["direct_factcheck", "corroborating", "matching_coverage", "related_context", "broader_context"]] = None
    discovery_basis: Optional[Literal["strong_match", "topic_overlap", "repeated_report", "full_text_context"]] = None
    additional_reports: int = 0
    repeated_by: list[str] = Field(default_factory=list)
    reviewed_claim: Optional[str] = None
    rating: Optional[str] = None
    claim_match_score: Optional[float] = None


class V1ClaimResult(BaseModel):
    claim: str
    status: Literal["supported", "contradicted", "mixed", "insufficient_evidence"]
    confidence: Literal["low", "medium", "high"]
    supporting_sources: list[V1EvidenceSource] = Field(default_factory=list)
    contradicting_sources: list[V1EvidenceSource] = Field(default_factory=list)
    related_sources: list[V1EvidenceSource] = Field(default_factory=list)
    context_sources: list[V1EvidenceSource] = Field(default_factory=list)
    context_notes: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    hidden_source_count: int = 0


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
    coverage_breadth: Literal["none", "limited", "partial", "broad"] = "none"
    context_breadth: Literal["none", "limited", "partial", "broad"] = "none"
    verification_strength: Literal["limited", "moderate", "strong"] = "limited"


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
    overall_evidence_summary: Optional[str] = None
    confidence: Optional[Literal["low", "medium", "high"]] = None
    factual_evidence: Optional[V1FactualEvidenceAssessment] = None
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
    """Map verdict-grade evidence and non-decisive context separately into v1."""
    direct_source = []
    if fact_check.source_url:
        direct_source.append(V1EvidenceSource(
            title=(f"Fact-check rating: {fact_check.rating}" if fact_check.rating else "Related fact-check"),
            publisher=fact_check.source, url=fact_check.source_url,
            reachable=fact_check.source_reachable, independent=True,
            source_type="secondary", stance="contextual" if fact_check.status == "mixed" else None,
            evidence_level=(
                "direct_factcheck"
                if fact_check.status in {"verified", "disputed", "mixed"}
                else "related_context"
            ),
            reviewed_claim=fact_check.reviewed_claim, rating=fact_check.rating,
            claim_match_score=fact_check.claim_match_score,
        ))

    def map_article(article: RelatedArticle) -> V1EvidenceSource:
        return V1EvidenceSource(
            title=article.title, publisher=article.source, url=article.url,
            relevance_score=article.relevance_score, published_at=article.published_at,
            recency=article.recency, reachable=article.reachable,
            independent=article.independent,
            semantic_relevance=article.semantic_relevance, stance=article.stance,
            source_type=article.source_type, evidence_level=article.evidence_level,
            discovery_basis=article.discovery_basis,
            additional_reports=article.additional_reports,
            repeated_by=article.repeated_by,
        )

    article_sources = [
        map_article(article) for article in (fact_check.related_articles or []) if article.url
    ]
    context_sources = [
        map_article(article) for article in (fact_check.context_articles or []) if article.url
    ]
    semantic_support = [source for source in article_sources if source.stance == "corroborating"]
    semantic_contradiction = [source for source in article_sources if source.stance == "contradicting"]
    contextual = [source for source in article_sources if source.stance not in {"corroborating", "contradicting"}]
    limitations, supporting, contradicting, related = [], [], [], []

    if fact_check.status == "verified":
        status, confidence, supporting, related = "supported", "high", direct_source, article_sources
        if related:
            limitations.append("Related reporting is shown separately from the direct fact-check evidence.")
    elif fact_check.status == "disputed":
        status, confidence, contradicting, related = "contradicted", "high", direct_source, article_sources
        if related:
            limitations.append("Related reporting is shown separately from the direct fact-check evidence.")
    elif fact_check.status == "mixed":
        status, confidence, related = "mixed", "medium" if direct_source else "low", direct_source + article_sources
        limitations.append("The available fact-check rating was mixed or context-dependent.")
    elif fact_check.evidence_status == "corroborated_reporting":
        status, confidence = "supported", "medium"
        supporting, related = semantic_support, contextual
        limitations.append(
            "This status is based on closely matching independent reporting or an authoritative primary source, not an adjudicated fact-check."
        )
    elif fact_check.evidence_status == "contradicted_reporting":
        status, confidence = "contradicted", "medium"
        contradicting, related = semantic_contradiction, contextual
        limitations.append(
            "This status is based on closely matching independent reporting or an authoritative primary source, not an adjudicated fact-check."
        )
    elif fact_check.evidence_status == "mixed_reporting":
        status, confidence = "mixed", "medium"
        supporting, contradicting, related = semantic_support, semantic_contradiction, contextual
        limitations.append("Independent reporting contained both corroborating and contradicting statements.")
    else:
        status, confidence, related = "insufficient_evidence", "low", direct_source + article_sources
        if fact_check.status == "opinion":
            limitations.append("This statement appears to be opinion or rhetoric rather than a checkable fact.")
    hidden_source_count = sum(
        isinstance(item, dict) for item in (fact_check.rejected_articles or [])
    )

    return V1ClaimResult(
        claim=fact_check.claim, status=status, confidence=confidence,
        supporting_sources=_deduplicate_v1_sources(supporting),
        contradicting_sources=_deduplicate_v1_sources(contradicting),
        related_sources=_deduplicate_v1_sources(related),
        context_sources=_deduplicate_v1_sources(context_sources),
        context_notes=[],
        limitations=limitations,
        hidden_source_count=hidden_source_count,
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
    def claim_has_matching_coverage(claim: V1ClaimResult) -> bool:
        sources = [
            *claim.supporting_sources,
            *claim.contradicting_sources,
            *claim.related_sources,
        ]
        return any(
            source.evidence_level in {"direct_factcheck", "corroborating", "matching_coverage"}
            for source in sources
        )

    def breadth(count: int) -> str:
        ratio = count / len(claims) if claims else 0.0
        if ratio >= 0.75:
            return "broad"
        if ratio >= 0.40:
            return "partial"
        if count:
            return "limited"
        return "none"

    claims_with_coverage = sum(claim_has_matching_coverage(claim) for claim in claims)
    claims_with_context = sum(bool(
        claim.context_sources or any(
            source.evidence_level == "related_context" for source in claim.related_sources
        )
    ) for claim in claims)
    coverage_breadth = breadth(claims_with_coverage)
    context_breadth = breadth(claims_with_context)

    common = {
        "claim_count": len(claims),
        "supported_count": counts["supported"],
        "contradicted_count": counts["contradicted"],
        "mixed_count": counts["mixed"],
        "insufficient_count": counts["insufficient"],
        "coverage_breadth": coverage_breadth,
        "context_breadth": context_breadth,
    }

    if classification and not classification.factual_verdict_allowed:
        return V1FactualEvidenceAssessment(
            status="not_applicable", confidence="low", verification_strength="limited",
            summary="FactScope did not assign an overall factual status to this type of content.",
            **common,
        )
    if processing_state == "processing":
        return V1FactualEvidenceAssessment(
            status="processing", confidence="low", verification_strength="limited",
            summary="Claim-level evidence is still being processed.",
            **common,
        )
    if not claims:
        return V1FactualEvidenceAssessment(
            status="insufficient_evidence", confidence="low", verification_strength="limited",
            summary="No claim-level evidence was available for an overall factual assessment.",
            **common,
        )

    decisive_kinds = int(counts["supported"] > 0) + int(counts["contradicted"] > 0)
    reporting_support = any(
        source.stance == "corroborating"
        for claim in claims for source in claim.supporting_sources
    )
    reporting_contradiction = any(
        source.stance == "contradicting"
        for claim in claims for source in claim.contradicting_sources
    )
    if counts["mixed"] or decisive_kinds > 1 or (
        counts["insufficient"] and (counts["supported"] or counts["contradicted"])
    ):
        status = "mixed"
        summary = "The checked claims have mixed outcomes or incomplete evidence."
    elif counts["supported"]:
        status = "supported"
        summary = (
            "Independent reporting or an authoritative primary source corroborates the checked claim or claims."
            if reporting_support else
            "The available direct fact-check evidence supports the checked claim or claims."
        )
    elif counts["contradicted"]:
        status = "contradicted"
        summary = (
            "Independent reporting or an authoritative primary source contradicts the checked claim or claims."
            if reporting_contradiction else
            "The available direct fact-check evidence contradicts the checked claim or claims."
        )
    else:
        status = "insufficient_evidence"
        if coverage_breadth == "broad":
            summary = "Matching independent coverage was found for most checked claims, but the available pages could not be inspected strongly enough for a factual verdict."
        elif coverage_breadth in {"partial", "limited"}:
            summary = "Matching coverage was found for some checked claims, while other claims still lack corroborating evidence."
        elif context_breadth != "none":
            summary = "Broader reporting and background context were found, but they do not directly confirm or contradict the checked claims."
        else:
            summary = "No useful external coverage was found for the checked claims."

    claim_confidences = [claim.confidence for claim in claims]
    if status == "insufficient_evidence" or processing_state != "complete":
        confidence = "low"
        verification_strength = "limited"
    elif claim_confidences and all(value == "high" for value in claim_confidences):
        confidence = "high"
        verification_strength = "strong"
    else:
        confidence = "medium"
        verification_strength = "moderate"

    return V1FactualEvidenceAssessment(
        status=status, confidence=confidence, verification_strength=verification_strength,
        summary=summary, **common,
    )
def _to_v1_analysis(legacy: AnalyzeResponse, fallback_analysis_id: str) -> V1AnalyzeResponse:
    classification = legacy.content_classification
    # Correct older cached classifications created before checkable breaking
    # news was eligible for an evidence status.
    if classification and (
        classification.content_type == "breaking_news"
        and classification.checkability != "no_checkable_claims"
        and not classification.factual_verdict_allowed
    ):
        classification = classification.model_copy(update={"factual_verdict_allowed": True})
    # Satire statements are not presented as failed literal fact checks, even
    # when an older cached analysis contains extracted claims.
    claims = [] if classification and classification.content_type == "satire" else [
        _map_v1_claim(item) for item in (legacy.fact_checks or [])
    ]
    provider_failed = _provider_failed(legacy)
    classification_complete = bool(classification and (
        classification.content_type == "unsupported_page"
        or classification.checkability == "no_checkable_claims"
    ))
    limitations = [
        "This assessment looks at the page's source, presentation, and available evidence. It does not guarantee that every claim is true."
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
        if classification.content_type == "breaking_news":
            limitations.append(
                "Breaking-news evidence may be incomplete or change as reporting develops."
            )
        elif classification.content_type == "satire":
            limitations.append(
                "Satire is not assessed as literal factual reporting."
            )
        elif classification.content_type == "opinion":
            limitations.append(
                "Viewpoints are not factual verdicts; specific checkable statements may still be assessed."
            )
        elif classification.content_type == "prediction":
            limitations.append(
                "Predicted future outcomes cannot yet be verified as true or false."
            )
        elif not classification.factual_verdict_allowed:
            label = classification.content_type.replace("_", " ")
            limitations.append(
                f"The page is classified as {label}; no literal factual verdict was assigned."
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
    legacy_payload["content_classification"] = (
        classification.model_dump() if classification else None
    )
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


class V1ImageProvenanceAssessment(BaseModel):
    status: Literal["visible_source_indicator", "no_visible_source_indicator", "unknown"]
    confidence: Literal["low", "medium"]
    summary: str
    indicators: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class V1ImageManipulationAssessment(BaseModel):
    status: Literal[
        "no_indicators_detected", "possible_manipulation",
        "likely_manipulated", "likely_ai_generated", "uncertain",
    ]
    confidence: Literal["low", "medium"]
    summary: str
    indicators: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class V1CaptionConsistencyAssessment(BaseModel):
    status: Literal[
        "consistent", "inconsistent", "mixed", "insufficient_evidence",
        "not_provided", "not_applicable",
    ]
    confidence: Literal["low", "medium", "high"]
    summary: str
    claims: list[V1ClaimResult] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class V1ImageAssessment(BaseModel):
    provenance: V1ImageProvenanceAssessment
    manipulation: V1ImageManipulationAssessment
    caption_consistency: V1CaptionConsistencyAssessment


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
    image_assessment: Optional[V1ImageAssessment] = None


class V1ImageVerifyResponse(ImageVerifyResponse):
    schema_version: Literal["1.0"] = "1.0"
    analysis_id: str
    processing_state: Literal["complete", "partial", "failed"]
    retryable: bool = False
    assessment: V1ImageAssessment
    limitations: list[str] = Field(default_factory=list)
    legacy_score: int
    legacy_verdict: str


def _build_image_assessment(
    provider_result: dict,
    claim_results: Optional[list[FactCheckResult]],
    caption_present: bool,
    caption_tone: str,
) -> V1ImageAssessment:
    verdict = str(provider_result.get("verdict") or "uncertain")
    score = max(0, min(100, int(provider_result.get("authenticity_score", 50))))
    visual_confidence = provider_result.get("visual_confidence", "low")
    if visual_confidence not in ("low", "medium", "high"):
        visual_confidence = "low"
    confidence = "medium" if visual_confidence in ("medium", "high") else "low"

    provenance_indicators = [
        str(item)[:240] for item in provider_result.get("provenance_indicators", [])
        if item
    ][:3]
    if provenance_indicators:
        provenance_status = "visible_source_indicator"
        provenance_confidence = "medium"
        provenance_summary = "Visible source or credit indicators were detected in the image."
    elif provider_result.get("explanation") or provider_result.get("evidence"):
        provenance_status = "no_visible_source_indicator"
        provenance_confidence = "low"
        provenance_summary = "No visible source or credit indicator was detected."
    else:
        provenance_status = "unknown"
        provenance_confidence = "low"
        provenance_summary = "Image provenance could not be assessed."

    provenance = V1ImageProvenanceAssessment(
        status=provenance_status,
        confidence=provenance_confidence,
        summary=provenance_summary,
        indicators=provenance_indicators,
        limitations=[
            "Visible credits and watermarks do not prove ownership, origin, or an unedited chain of custody."
        ],
    )

    manipulation_indicators = [
        str(item)[:240] for item in provider_result.get("manipulation_indicators", [])
        if item
    ][:3]
    if not manipulation_indicators and verdict in ("ai_generated", "manipulated"):
        manipulation_indicators = [
            str(item)[:240] for item in provider_result.get("evidence", []) if item
        ][:3]

    if verdict == "ai_generated":
        manipulation_status = "likely_ai_generated"
        manipulation_summary = "The visual analysis found indicators associated with AI generation."
    elif verdict == "manipulated":
        manipulation_status = "likely_manipulated"
        manipulation_summary = "The visual analysis found indicators associated with image manipulation."
    elif verdict == "authentic" and score >= 70:
        manipulation_status = "no_indicators_detected"
        manipulation_summary = "No clear AI-generation or manipulation indicators were detected."
    elif verdict == "out_of_context":
        manipulation_status = "uncertain"
        manipulation_summary = "Visual inspection cannot determine whether the image is used in the correct context."
        confidence = "low"
    elif manipulation_indicators:
        manipulation_status = "possible_manipulation"
        manipulation_summary = "Some visual indicators warrant further inspection."
    else:
        manipulation_status = "uncertain"
        manipulation_summary = "The visual evidence was not sufficient for a manipulation assessment."

    provider_limitations = [
        str(item)[:240] for item in provider_result.get("limitations", []) if item
    ][:3]
    manipulation = V1ImageManipulationAssessment(
        status=manipulation_status,
        confidence=confidence,
        summary=manipulation_summary,
        indicators=manipulation_indicators,
        limitations=provider_limitations + [
            "This is a model-based visual assessment, not a forensic or cryptographic verification."
        ],
    )

    mapped_claims = [_map_v1_claim(item) for item in (claim_results or [])]
    if not caption_present:
        caption_status = "not_provided"
        caption_confidence = "low"
        caption_summary = "No caption or contextual claim was provided."
        caption_limitations = []
    elif caption_tone == "opinion_or_rhetorical":
        caption_status = "not_applicable"
        caption_confidence = "low"
        caption_summary = "The caption appears opinion-based or rhetorical rather than fact-checkable."
        caption_limitations = ["An opinion classification does not mean the caption is false."]
    elif not mapped_claims:
        caption_status = "insufficient_evidence"
        caption_confidence = "low"
        caption_summary = "No direct evidence was available to evaluate caption consistency."
        caption_limitations = ["Related coverage alone is not treated as direct caption evidence."]
    else:
        statuses = {claim.status for claim in mapped_claims}
        if "mixed" in statuses or (
            "supported" in statuses and "contradicted" in statuses
        ) or (
            "insufficient_evidence" in statuses
            and ("supported" in statuses or "contradicted" in statuses)
        ):
            caption_status = "mixed"
            caption_summary = "The caption claims have mixed outcomes or incomplete evidence."
        elif statuses == {"supported"}:
            caption_status = "consistent"
            caption_summary = "Direct evidence supports the checked caption claim or claims."
        elif statuses == {"contradicted"}:
            caption_status = "inconsistent"
            caption_summary = "Direct evidence contradicts the checked caption claim or claims."
        else:
            caption_status = "insufficient_evidence"
            has_matching_coverage = any(
                source.evidence_level == "matching_coverage"
                for claim in mapped_claims for source in claim.related_sources
            )
            has_broader_context = any(claim.context_sources for claim in mapped_claims)
            if has_matching_coverage:
                caption_summary = "Matching coverage was found for the caption claim, but it was not strong enough to establish consistency."
            elif has_broader_context:
                caption_summary = "Broader context was found for the caption claim, but it does not directly establish consistency."
            else:
                caption_summary = "No useful external coverage was found to evaluate caption consistency."
        if caption_status in ("insufficient_evidence", "mixed"):
            caption_confidence = "low" if caption_status == "insufficient_evidence" else "medium"
        elif all(claim.confidence == "high" for claim in mapped_claims):
            caption_confidence = "high"
        else:
            caption_confidence = "medium"
        caption_limitations = []

    caption_consistency = V1CaptionConsistencyAssessment(
        status=caption_status,
        confidence=caption_confidence,
        summary=caption_summary,
        claims=mapped_claims,
        limitations=caption_limitations,
    )
    return V1ImageAssessment(
        provenance=provenance,
        manipulation=manipulation,
        caption_consistency=caption_consistency,
    )


def _to_v1_image_analysis(
    legacy: ImageVerifyResponse,
    fallback_analysis_id: str,
    caption_present: bool = False,
    caption_tone: str = "informal",
) -> V1ImageVerifyResponse:
    explanation = (legacy.explanation or "").lower()
    timed_out = "timed out" in explanation
    provider_failed = any(marker in explanation for marker in (
        "could not be completed", "rate limit reached", "content safety filters",
    ))
    fetch_failed = "could not fetch the image" in explanation
    failed = timed_out or provider_failed or fetch_failed
    if failed:
        assessment = _build_image_assessment(
            {
                "authenticity_score": 50,
                "verdict": "uncertain",
                "visual_confidence": "low",
            },
            None,
            caption_present,
            caption_tone,
        )
    else:
        assessment = legacy.image_assessment or _build_image_assessment(
            {
                "authenticity_score": legacy.authenticity_score,
                "verdict": legacy.verdict,
                "explanation": legacy.explanation,
                "evidence": legacy.evidence,
                "visual_confidence": "low",
            },
            legacy.claim_analysis,
            caption_present,
            caption_tone,
        )
    limitations = list(dict.fromkeys(
        assessment.provenance.limitations
        + assessment.manipulation.limitations
        + assessment.caption_consistency.limitations
    ))
    if failed:
        limitations.append("No visual conclusion should be inferred from this technical failure.")
    payload = legacy.model_dump()
    payload.pop("image_assessment", None)
    return V1ImageVerifyResponse(
        **payload,
        analysis_id=legacy.fingerprint or fallback_analysis_id,
        processing_state="failed" if failed else "complete",
        retryable=timed_out or provider_failed,
        assessment=assessment,
        limitations=limitations,
        legacy_score=legacy.authenticity_score,
        legacy_verdict=legacy.verdict,
    )


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
        cached_assessment = (
            V1ImageAssessment(**cached["image_assessment"])
            if cached.get("image_assessment") else None
        )
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
            image_assessment=cached_assessment,
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
        logger.info("Caption is opinion/rhetorical; factual claim verification skipped")
    elif caption and caption_tone == "informal":
        logger.info("Skipping claim verification — caption tone is informal")

    final_score = result["authenticity_score"]
    final_verdict = result["verdict"]
    final_explanation = result["explanation"]

    # Caption evidence is reported separately and never changes the visual
    # authenticity score or manipulation verdict.
    image_assessment = _build_image_assessment(
        result, claim_results, bool(caption.strip()), caption_tone
    )

    try:
        store_image_scan(request.image_url, {
            "authenticity_score": final_score,
            "verdict": final_verdict,
            "explanation": final_explanation,
            "evidence": result["evidence"],
            "claim_analysis": [c.model_dump() for c in claim_results] if claim_results else None,
        }, user_id=subject_id, analysis_version=ANALYSIS_VERSION,
           page_url=request.page_url, og_image=request.image_url,
           image_assessment=image_assessment.model_dump())
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
        image_assessment=image_assessment,
    )


@app.post("/v1/analyze/verify-image", response_model=V1ImageVerifyResponse)
async def verify_image_v1(request: ImageVerifyRequest, http_request: Request):
    """Return separated provenance, manipulation, and caption assessments."""
    legacy = await verify_image(request, http_request)
    if not isinstance(legacy, ImageVerifyResponse):
        return legacy
    caption = ""
    if request.social_context and request.social_context.get("post_text"):
        caption = str(request.social_context["post_text"])
    elif request.page_text:
        caption = request.page_text[:500]
    return _to_v1_image_analysis(
        legacy,
        _request_id(http_request),
        caption_present=bool(caption.strip()),
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
            if factcheck_available() and request.text and pre_classification.content_type != "satire":
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

    pre_claim_classification = classify_page_content(
        title=request.title,
        text=request.text,
        url=request.url,
        metadata=meta_dict,
        llm_result=llm_result,
    )
    suppress_literal_claims = pre_claim_classification.get("content_type") == "satire"
    if suppress_literal_claims:
        if fc_future is not None:
            fc_future.cancel()
        claims_completed = True
        fact_checks = []
    elif fc_future is not None:
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
    claims = [_map_v1_claim(item) for item in fact_checks]
    factual_evidence = _build_factual_evidence_assessment(claims, "complete", None)
    return V1ClaimsResponse(
        analysis_id=analysis_id,
        processing_state="complete",
        claims=claims,
        overall_evidence_summary=factual_evidence.summary,
        confidence=factual_evidence.confidence,
        factual_evidence=factual_evidence,
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
    """Create a public snapshot only from an analysis stored by FactScope."""
    auth_context = _require_session(http_request)
    fingerprint = request.fingerprint
    if fingerprint.startswith("img:"):
        stored = find_image_scan_by_fingerprint(fingerprint)
        if not stored:
            raise HTTPException(status_code=404, detail="Stored analysis not found")
        scanned_url = stored.get("page_url", "") or stored.get("image_url", "")
        raw_claims = stored.get("claim_analysis")
        if isinstance(raw_claims, str):
            try:
                raw_claims = json.loads(raw_claims)
            except (json.JSONDecodeError, TypeError):
                raw_claims = None
        claims = [FactCheckResult(**item) for item in raw_claims] if raw_claims else None
        raw_assessment = stored.get("image_assessment")
        assessment = V1ImageAssessment(**raw_assessment) if raw_assessment else None
        legacy = ImageVerifyResponse(
            authenticity_score=stored.get("authenticity_score", 50),
            verdict=stored.get("verdict", "uncertain"),
            explanation=stored.get("explanation", ""),
            evidence=stored.get("evidence", []),
            claim_analysis=claims,
            fingerprint=fingerprint,
            analysis_version=stored.get("analysis_version"),
            image_assessment=assessment,
        )
        snapshot = _to_v1_image_analysis(
            legacy, fingerprint, caption_present=bool(claims)
        ).model_dump()
        data = {
            "result_type": "image",
            "score": legacy.authenticity_score,
            "verdict": legacy.verdict,
            "explanation": legacy.explanation,
            "evidence": legacy.evidence,
            "scanned_url": scanned_url,
            "scanned_title": stored.get("scanned_title", ""),
            "og_image": stored.get("og_image", "") or stored.get("image_url", ""),
            "fingerprint": fingerprint,
            "analysis_version": stored.get("analysis_version", ""),
            "scan_timestamp": stored.get("timestamp", ""),
            "snapshot": snapshot,
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
        raw_claims = stored.get("judgement")
        if isinstance(raw_claims, str):
            try:
                raw_claims = json.loads(raw_claims)
            except (json.JSONDecodeError, TypeError):
                raw_claims = None
        claims = [FactCheckResult(**item) for item in raw_claims] if raw_claims is not None else None
        source_info = SourceInfo(**stored["source_info"]) if stored.get("source_info") else None
        classification = (
            ContentClassification(**stored["content_classification"])
            if stored.get("content_classification") else None
        )
        source_quality = (
            V1SourceQualityAssessment(**stored["source_quality"])
            if stored.get("source_quality") else None
        )
        legacy = AnalyzeResponse(
            trust_score=stored.get("trust_score", 50),
            verdict=stored.get("verdict", "uncertain"),
            explanation=stored.get("explanation", ""),
            evidence=stored.get("evidence", []),
            source_info=source_info,
            fact_checks=claims,
            fingerprint=fingerprint,
            claims_pending=raw_claims is None,
            analysis_version=stored.get("analysis_version"),
            content_classification=classification,
            source_quality=source_quality,
        )
        snapshot = _to_v1_analysis(legacy, fingerprint).model_dump()
        data = {
            "result_type": "page",
            "score": legacy.trust_score,
            "verdict": legacy.verdict,
            "explanation": legacy.explanation,
            "evidence": legacy.evidence,
            "domain": domain,
            "source_info": stored.get("source_info"),
            "scanned_url": scanned_url,
            "scanned_title": stored.get("scanned_title", ""),
            "og_image": stored.get("og_image", ""),
            "fingerprint": fingerprint,
            "analysis_version": stored.get("analysis_version", ""),
            "scan_timestamp": stored.get("timestamp", ""),
            "snapshot": snapshot,
        }
    data["owner_subject_id"] = auth_context.subject_id
    share_id = store_shared_result(data)
    base = "http://localhost:8000" if ENVIRONMENT == "development" else "https://factscope-api.onrender.com"
    return {"share_url": f"{base}/s/{share_id}", "share_id": share_id}

_SHARE_TEMPLATE = (Path(__file__).parent / "templates" / "share.html").read_text(encoding="utf-8")

def _share_status_view(snapshot: dict, result_type: str, fallback_verdict: str) -> tuple[str, str, str]:
    """Return the same cautious public label, confidence, and summary as v1 UI."""
    if result_type == "image":
        manipulation = ((snapshot.get("assessment") or {}).get("manipulation") or {})
        labels = {
            "no_indicators_detected": "No visible manipulation indicators",
            "possible_manipulation": "Possible editing indicators",
            "likely_manipulated": "Edited or composited image detected",
            "likely_ai_generated": "Likely AI-generated",
            "uncertain": "Visual assessment uncertain",
        }
        status = manipulation.get("status", "uncertain")
        return labels.get(status, "Visual assessment uncertain"), manipulation.get("confidence", "low"), (
            manipulation.get("summary") or "No visual assessment summary is available."
        )
    factual = snapshot.get("factual_evidence") or {}
    classification = snapshot.get("content_classification") or {}
    status = factual.get("status", "insufficient_evidence")
    coverage = factual.get("coverage_breadth", "none")
    context_breadth = factual.get("context_breadth", "none")
    if status == "not_applicable":
        label = {
            "satire": "Satire identified", "opinion": "Opinion and context assessment",
            "prediction": "Forward-looking claim", "unsupported_page": "Unable to assess this page",
        }.get(classification.get("content_type"), "Context-only assessment")
    elif status == "insufficient_evidence" and coverage == "broad":
        label = "Matching coverage found"
    elif status == "insufficient_evidence" and coverage in {"partial", "limited"}:
        label = "Some matching coverage found"
    elif status == "insufficient_evidence" and context_breadth != "none":
        label = "Context found; verification remains open"
    elif status == "insufficient_evidence" and classification.get("content_type") == "breaking_news":
        label = "Evidence still developing"
    elif status == "insufficient_evidence":
        label = "No external coverage found"
    else:
        claims = snapshot.get("claims") or []
        reporting_support = any(
            isinstance(source, dict) and source.get("stance") == "corroborating"
            for claim in claims for source in (claim.get("supporting_sources") or [])
        )
        reporting_contradiction = any(
            isinstance(source, dict) and source.get("stance") == "contradicting"
            for claim in claims for source in (claim.get("contradicting_sources") or [])
        )
        if status == "supported" and reporting_support:
            label = "Supported by independent reporting"
        elif status == "contradicted" and reporting_contradiction:
            label = "Contradicted by independent reporting"
        else:
            label = {
                "supported": "Supported by direct evidence", "contradicted": "Contradicted by direct evidence",
                "mixed": "Mixed evidence", "processing": "Evidence check in progress",
            }.get(status, "Evidence assessment")
    return label, factual.get("confidence", snapshot.get("confidence", "low")), (
        snapshot.get("overall_evidence_summary") or factual.get("summary")
        or "No evidence summary is available."
    )

def _render_share_page(data: dict, share_url: str = "") -> str:
    import html as _html
    from urllib.parse import quote

    def esc(value: object, limit: int = 2000) -> str:
        return _html.escape(str(value or "")[:limit], quote=True)

    def safe_http_url(value: object) -> str:
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

    def sources_html(sources: object, heading: str = "") -> str:
        if not isinstance(sources, list) or not sources:
            return ""
        items = []
        for source in sources[:8]:
            if not isinstance(source, dict):
                continue
            title = esc(source.get("title") or source.get("publisher") or "Evidence source", 240)
            publisher = esc(source.get("publisher"), 120)
            url = safe_http_url(source.get("url"))
            link = f'<a href="{esc(url)}" target="_blank" rel="noopener">{title}</a>' if url else title
            meta = []
            if publisher:
                meta.append(publisher)
            if source.get("independent") is False:
                meta.append("Repeated or non-independent")
            additional = max(0, int(source.get("additional_reports") or 0))
            if additional:
                meta.append(f"+{additional} similar result{'s' if additional != 1 else ''} grouped")
            publisher_html = f'<span>{" · ".join(meta)}</span>' if meta else ""
            items.append(f"<li>{link}{publisher_html}</li>")
        if not items:
            return ""
        heading_html = f'<div class="source-heading">{esc(heading)}</div>' if heading else ""
        visible = "".join(items[:4])
        remaining = "".join(items[4:])
        more_html = (
            f'<details class="more-sources"><summary>Show {len(items) - 4} more source'
            f'{"" if len(items) - 4 == 1 else "s"}</summary><ul>{remaining}</ul></details>'
            if remaining else ""
        )
        return f'<div class="source-group">{heading_html}<ul>{visible}</ul>{more_html}</div>'
    result_type = "image" if data.get("result_type") == "image" else "page"
    snapshot = data.get("snapshot") if isinstance(data.get("snapshot"), dict) else {}
    is_legacy = not bool(snapshot)
    if is_legacy:
        snapshot = {
            "explanation": data.get("explanation", ""),
            "evidence": data.get("evidence", []),
        }
    status_label, confidence, summary = _share_status_view(
        snapshot, result_type, str(data.get("verdict", "uncertain"))
    ) if not is_legacy else (
        "Legacy analysis snapshot", "unknown",
        data.get("explanation") or "This older link contains a limited compatibility snapshot.",
    )

    domain_raw = str(data.get("domain", "") or "")[:253]
    domain = esc(domain_raw, 253)
    scanned_url = safe_http_url(data.get("scanned_url", ""))
    scanned_title = esc(data.get("scanned_title", ""), 500)
    preview_image = safe_http_url(data.get("og_image", ""))
    analysis_version = esc(data.get("analysis_version", "") or snapshot.get("analysis_version", ""), 80)
    scan_timestamp = esc(data.get("scan_timestamp", ""), 80)
    processing_state = esc(snapshot.get("processing_state", "complete" if not is_legacy else "legacy"), 40)

    image_html = ""
    if preview_image:
        image_html = f'<img id="previewImage" class="preview-image" src="{esc(preview_image)}" alt="Scanned content preview">'
    source_mark = esc((domain_raw[:1] or "F").upper(), 1)
    title_html = f'<h1 class="preview-title">{scanned_title}</h1>' if scanned_title else ""
    domain_html = f'<div class="preview-source"><span class="source-mark">{source_mark}</span><span>{domain}</span></div>' if domain else ""
    url_html = f'<a class="preview-url" href="{esc(scanned_url)}" target="_blank" rel="noopener">Open original content</a>' if scanned_url else ""
    unavailable_class = " hidden" if preview_image else ""
    preview_html = (
        f'<section class="preview" aria-label="Scanned content context">{image_html}'
        f'<div class="preview-body"><div class="eyebrow">Scanned content</div>{title_html}{domain_html}{url_html}'
        f'<div id="previewUnavailable" class="preview-unavailable{unavailable_class}">Preview image unavailable</div></div></section>'
    )

    claims = []
    if result_type == "image":
        claims = ((((snapshot.get("assessment") or {}).get("caption_consistency") or {}).get("claims")) or [])
    else:
        claims = snapshot.get("claims") or []
    claim_items = []
    for claim in claims[:6]:
        if not isinstance(claim, dict):
            continue
        related_sources = claim.get("related_sources") or []
        matching = [
            item for item in related_sources if isinstance(item, dict) and (
                item.get("evidence_level") == "matching_coverage"
                or (not item.get("evidence_level") and item.get("stance") == "unavailable")
            )
        ]
        related = [item for item in related_sources if item not in matching]
        broader = claim.get("context_sources") or []
        claim_status = str(claim.get("status") or "insufficient_evidence")
        reporting_support = any(
            isinstance(item, dict) and item.get("stance") == "corroborating"
            for item in (claim.get("supporting_sources") or [])
        )
        reporting_contradiction = any(
            isinstance(item, dict) and item.get("stance") == "contradicting"
            for item in (claim.get("contradicting_sources") or [])
        )
        if claim_status == "supported" and claim.get("confidence") == "medium" and reporting_support:
            claim_label = "Corroborated by independent reporting"
        elif claim_status == "contradicted" and claim.get("confidence") == "medium" and reporting_contradiction:
            claim_label = "Contradicted by independent reporting"
        elif claim_status == "insufficient_evidence" and len(matching) > 1:
            claim_label = "Multiple matching reports"
        elif claim_status == "insufficient_evidence" and len(matching) == 1:
            claim_label = "Matching coverage"
        elif claim_status == "insufficient_evidence" and related:
            claim_label = "Related reporting found"
        elif claim_status == "insufficient_evidence" and broader:
            claim_label = "Broader context found"
        elif claim_status == "insufficient_evidence":
            claim_label = "No external coverage found"
        else:
            claim_label = {
                "supported": "Supported by direct evidence", "contradicted": "Contradicted by direct evidence",
                "mixed": "Mixed evidence",
            }.get(claim_status, claim_status.replace("_", " ").title())
        broader_heading = "" if claim_label == "Broader context found" else "Broader context"
        source_sections = (
            sources_html(claim.get("supporting_sources"), "Supporting sources")
            + sources_html(claim.get("contradicting_sources"), "Contradicting sources")
            + sources_html(matching)
            + sources_html(related, "Related reporting")
            + sources_html(broader, broader_heading)
        )
        claim_confidence = esc(claim.get("confidence", "low"))
        confidence_html = "" if claim_status == "insufficient_evidence" else (
            f"<span>{claim_confidence.title()} evidence confidence</span>"
        )
        claim_items.append(
            f'<article class="claim"><div class="claim-text">{esc(claim.get("claim"), 600)}</div>'
            f'<div class="claim-meta"><strong>{esc(claim_label)}</strong>{confidence_html}</div>'
            f'{source_sections}</article>'
        )
    claim_section_title = "Caption claim evidence" if result_type == "image" else "Claim evidence"
    claims_html = (
        f'<section class="card"><div class="card-heading">{claim_section_title}</div>{"".join(claim_items)}</section>'
        if claim_items else ""
    )

    image_assessment_html = ""
    if result_type == "image" and not is_legacy:
        assessment = snapshot.get("assessment") or {}
        manipulation = assessment.get("manipulation") or {}
        caption = assessment.get("caption_consistency") or {}
        provenance = assessment.get("provenance") or {}
        indicators = [str(item) for item in (manipulation.get("indicators") or []) if item]
        provenance_indicators = [str(item) for item in (provenance.get("indicators") or []) if item]
        indicator_html = "".join(f"<li>{esc(item, 300)}</li>" for item in indicators[:5])
        provenance_html = "".join(f"<li>{esc(item, 300)}</li>" for item in provenance_indicators[:5])
        provenance_list = f"<ul>{provenance_html}</ul>" if provenance_html else ""
        visual_block = (
            '<div class="mini-assessment wide"><div class="card-heading">Visual indicators</div>'
            f'<ul>{indicator_html}</ul></div>'
            if indicator_html else ""
        )
        image_assessment_html = (
            '<section class="card assessment-grid">'
            '<div class="mini-assessment"><div class="card-heading">Caption consistency</div>'
            f'<strong>{esc(str(caption.get("status") or "insufficient_evidence").replace("_", " ").title())}</strong>'
            f'<p>{esc(caption.get("summary"), 800)}</p></div>'
            '<div class="mini-assessment"><div class="card-heading">Visible provenance</div>'
            f'<strong>{esc(str(provenance.get("status") or "unknown").replace("_", " ").title())}</strong>'
            f'<p>{esc(provenance.get("summary"), 800)}</p>{provenance_list}</div>'
            f'{visual_block}</section>'
        )
    factual = snapshot.get("factual_evidence") or {}
    counts_html = ""
    if result_type == "page" and factual:
        if factual.get("status") == "insufficient_evidence":
            def has_matching(claim: dict) -> bool:
                sources = [
                    *(claim.get("supporting_sources") or []),
                    *(claim.get("contradicting_sources") or []),
                    *(claim.get("related_sources") or []),
                ]
                return any(
                    isinstance(source, dict) and source.get("evidence_level") in {
                        "direct_factcheck", "corroborating", "matching_coverage",
                    }
                    for source in sources
                )

            def has_context(claim: dict) -> bool:
                return bool(claim.get("context_sources")) or any(
                    isinstance(source, dict) and source.get("evidence_level") == "related_context"
                    for source in (claim.get("related_sources") or [])
                )

            claim_dicts = [claim for claim in claims if isinstance(claim, dict)]
            matching_count = sum(has_matching(claim) for claim in claim_dicts)
            context_count = sum(not has_matching(claim) and has_context(claim) for claim in claim_dicts)
            no_coverage_count = max(0, len(claim_dicts) - matching_count - context_count)
            counts = [
                ("Checked claims", len(claim_dicts)),
                ("With matching reporting", matching_count),
                ("With background context", context_count),
                ("Without useful coverage", no_coverage_count),
            ]
        else:
            counts = [
                ("Claims", factual.get("claim_count", 0)),
                ("Supported", factual.get("supported_count", 0)),
                ("Contradicted", factual.get("contradicted_count", 0)),
                ("Insufficient", factual.get("insufficient_count", 0)),
            ]
        counts_html = '<div class="counts">' + "".join(
            f'<div><strong>{int(value or 0)}</strong><span>{esc(label)}</span></div>' for label, value in counts
        ) + '</div>'

    model_evidence = snapshot.get("evidence") or data.get("evidence") or []
    model_items = "".join(f'<li>{esc(item, 500)}</li>' for item in model_evidence[:5])
    model_html = ""
    if snapshot.get("explanation") or model_items:
        model_html = (
            '<details class="card details"><summary>Content and source assessment</summary>'
            f'<p>{esc(snapshot.get("explanation"), 1600)}</p>'
            f'{f"<ul>{model_items}</ul>" if model_items else ""}'
            '<div class="caveat">AI-assisted review of presentation, attribution, and risk signals. It does not verify individual factual claims.</div></details>'
        )

    limitations = []
    for item in snapshot.get("limitations") or []:
        if not item:
            continue
        lowered = str(item).lower()
        if "legacy score" in lowered and "probability" in lowered:
            item = "This assessment looks at the page's source, presentation, and available evidence. It does not guarantee that every claim is true."
        if "at least one claim lacks enough evidence" in lowered:
            continue
        if item not in limitations:
            limitations.append(item)
    limitations_html = ""
    if limitations:
        items = "".join(f"<li>{esc(item, 500)}</li>" for item in limitations[:8])
        limitations_html = f'<details class="card details"><summary>About this assessment</summary><ul>{items}</ul></details>'

    metadata_parts = [f"State: {processing_state}"]
    if scan_timestamp:
        metadata_parts.append(f"Scanned: {scan_timestamp}")
    if analysis_version:
        metadata_parts.append(f"Analysis: {analysis_version}")
    metadata_html = "".join(f"<span>{part}</span>" for part in metadata_parts)
    legacy_score = max(0, min(100, int(data.get("score", 50))))
    compatibility_html = (
        f'<details class="compat"><summary>Compatibility score: {legacy_score}/100</summary>'
        '<p>This older score combines an automated review with basic page signals. Use the evidence above to understand the result.</p></details>'
    )

    card_url = f"{share_url}/card.png" if share_url else ""
    og_image_meta = (
        f'<meta property="og:image" content="{esc(card_url)}"><meta property="og:image:width" content="1200">'
        f'<meta property="og:image:height" content="630"><meta name="twitter:image" content="{esc(card_url)}">'
        if card_url else ""
    )
    meta_description = esc(summary, 200)
    page_title = esc(f"FactScope verification snapshot — {status_label}", 160)

    share_buttons_html = ""
    if share_url:
        share_text = f"FactScope AI-assisted verification snapshot for {domain_raw or 'shared content'}: {status_label}."
        encoded_text = quote(share_text)
        encoded_url = quote(share_url)
        full_msg = quote(f"{share_text}\n{share_url}")
        share_buttons_html = (
            '<div class="share-bar"><span>Share this snapshot</span>'
            f'<a href="https://twitter.com/intent/tweet?text={encoded_text}&url={encoded_url}" target="_blank" rel="noopener">X / Twitter</a>'
            f'<a href="https://api.whatsapp.com/send?text={full_msg}" target="_blank" rel="noopener">WhatsApp</a>'
            f'<button id="copyLink" data-url="{esc(share_url)}">Copy link</button></div>'
        )

    if result_type == "page" and factual.get("status") == "insufficient_evidence":
        assessment_meta = (
            f'Coverage: {esc(str(factual.get("coverage_breadth") or "none").replace("_", " ")).title()}'
            f' · Context: {esc(str(factual.get("context_breadth") or "none").replace("_", " ")).title()}'
            f' · Evidence strength: {esc(str(factual.get("verification_strength") or "limited").replace("_", " ")).title()}'
        )
    else:
        assessment_meta = f'Evidence confidence: {esc(confidence).title()}'
    snapshot_html = (
        '<main class="result"><section class="assessment">'
        '<div class="eyebrow">AI-assisted verification snapshot</div>'
        f'<div class="status">{esc(status_label)}</div><div class="confidence">{assessment_meta}</div>'
        f'<p class="summary">{esc(summary, 1600)}</p>{counts_html}<div class="metadata">{metadata_html}</div>'
        f'</section>{image_assessment_html}{claims_html}{model_html}{limitations_html}{compatibility_html}</main>'
    )
    return _SHARE_TEMPLATE.format(
        page_title=page_title,
        meta_description=meta_description,
        og_image_meta=og_image_meta,
        layout_class="" if preview_image else "no-preview-image",
        preview_html=preview_html,
        snapshot_html=snapshot_html,
        share_buttons_html=share_buttons_html,
    )


def _share_card_png(data: dict) -> bytes:
    """Generate a deterministic branded card without publisher-hosted imagery."""
    from io import BytesIO
    from textwrap import wrap
    from PIL import Image, ImageDraw, ImageFont

    snapshot = data.get("snapshot") if isinstance(data.get("snapshot"), dict) else {}
    result_type = "image" if data.get("result_type") == "image" else "page"
    label, confidence, summary = _share_status_view(
        snapshot, result_type, str(data.get("verdict", "uncertain"))
    ) if snapshot else ("Legacy analysis snapshot", "unknown", data.get("explanation", ""))
    domain = str(data.get("domain") or "Shared content")[:70]

    image = Image.new("RGB", (1200, 630), "#0f172a")
    draw = ImageDraw.Draw(image)
    fallback_font = False
    try:
        title_font = ImageFont.truetype("DejaVuSans-Bold.ttf", 52)
        body_font = ImageFont.truetype("DejaVuSans.ttf", 30)
        small_font = ImageFont.truetype("DejaVuSans.ttf", 24)
        brand_font = ImageFont.truetype("DejaVuSans-Bold.ttf", 32)
    except OSError:
        fallback_font = True
        title_font = body_font = small_font = brand_font = ImageFont.load_default()

    def card_text(value: object) -> str:
        rendered = str(value or "")
        return rendered.encode("latin-1", "replace").decode("latin-1") if fallback_font else rendered

    label = card_text(label)
    summary = card_text(summary)
    domain = card_text(domain)
    draw.rounded_rectangle((55, 45, 1145, 585), radius=32, fill="#ffffff")
    draw.ellipse((95, 85, 155, 145), fill="#4f46e5")
    draw.line((112, 116, 125, 129, 144, 101), fill="#ffffff", width=7, joint="curve")
    draw.text((175, 91), "FactScope", font=brand_font, fill="#111827")
    draw.text((95, 172), domain, font=small_font, fill="#64748b")
    y = 225
    for line in wrap(label, width=32)[:2]:
        draw.text((95, y), line, font=title_font, fill="#111827")
        y += 64
    draw.text((95, y + 4), f"{str(confidence).title()} confidence", font=small_font, fill="#4f46e5")
    y += 62
    for line in wrap(str(summary or "No summary available."), width=67)[:3]:
        draw.text((95, y), line, font=body_font, fill="#334155")
        y += 42
    draw.text((95, 535), card_text("AI-assisted verification snapshot - not a conclusive determination"), font=small_font, fill="#64748b")
    output = BytesIO()
    image.save(output, format="PNG", optimize=True)
    return output.getvalue()


@app.get("/s/{share_id}/card.png")
async def view_shared_card(share_id: str):
    data = get_shared_result(share_id)
    if not data:
        raise HTTPException(status_code=404, detail="Shared result not found")
    cached = get_shared_card(share_id)
    if cached:
        return Response(cached, media_type="image/png", headers={"Cache-Control": "public, max-age=86400"})
    card = _share_card_png(data)
    update_shared_card(share_id, card)
    return Response(card, media_type="image/png", headers={"Cache-Control": "public, max-age=86400"})

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
