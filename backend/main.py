from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from analyzers import text_analyzer, image_analyzer, pdf_analyzer, video_analyzer, url_analyzer
from elastic_utils import store_analysis_result, find_by_fingerprint, find_flagged_similar
from llm_utils import get_structured_analysis
from scoring import compute_structural_score
from fingerprinting import compute_fingerprint
from trust_graph import update_domain_stats, compute_domain_trust_signal
from fact_checker import verify_claims as _verify_claims, is_available as factcheck_available
from config import TEXT_MODEL_ID, MULTIMODAL_MODEL_ID, DEFAULT_MAX_TOKENS, DEFAULT_TEMPERATURE
import uvicorn
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="FactScope API", version="0.4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

LLM_WEIGHT = 0.65
STRUCTURAL_WEIGHT = 0.35


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
    json_ld_type: Optional[str] = None


class AnalyzeRequest(BaseModel):
    url: Optional[str] = None
    title: Optional[str] = None
    text: Optional[str] = None
    links: Optional[list[str]] = None
    metadata: Optional[PageMetadata] = None
    video_info: Optional[VideoInfo] = None
    sample_img: Optional[str] = None


class SourceInfo(BaseModel):
    site_name: Optional[str] = None
    author: Optional[str] = None
    publish_date: Optional[str] = None
    domain: Optional[str] = None


class FactCheckResult(BaseModel):
    claim: str
    status: str
    source: Optional[str] = None
    source_url: Optional[str] = None
    rating: Optional[str] = None
    source_count: Optional[int] = None
    corroboration: Optional[str] = None


class AnalyzeResponse(BaseModel):
    trust_score: int
    verdict: str
    explanation: str
    evidence: list[str]
    source_info: Optional[SourceInfo] = None
    structural_signals: Optional[list[dict]] = None
    fact_checks: Optional[list[FactCheckResult]] = None
    cached: Optional[bool] = None


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_page(request: AnalyzeRequest):
    """Unified endpoint for the browser extension."""

    # ── Fingerprint check (instant cache) ─────────────────────────────
    fingerprint = compute_fingerprint(request.text) if request.text else None

    if fingerprint:
        cached = find_by_fingerprint(fingerprint)
        if cached:
            logger.info("Returning cached result for fingerprint %s", fingerprint[:16])
            return AnalyzeResponse(
                trust_score=cached.get("trust_score", 50),
                verdict=cached.get("verdict", "suspicious"),
                explanation=cached.get("explanation", ""),
                evidence=cached.get("evidence", []),
                cached=True,
            )

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
        )

    # ── Run LLM analysis + fact-checking in parallel ────────────────────
    llm_result = None
    fact_checks = []

    with ThreadPoolExecutor(max_workers=2) as pool:
        llm_future = pool.submit(get_structured_analysis, combined)
        fc_future = None
        if factcheck_available() and request.text:
            fc_future = pool.submit(_verify_claims, request.text, request.title or "")

        llm_result = llm_future.result()
        if fc_future is not None:
            try:
                fact_checks = fc_future.result()
            except Exception as exc:
                logger.warning("Fact-check pipeline failed: %s", exc)

    # ── Run structural scoring ────────────────────────────────────────
    meta_dict = request.metadata.model_dump() if request.metadata else {}
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
            structural_score = max(0, min(100, structural_score + domain_signal["delta"]))

    # ── AI video platform signal ──────────────────────────────────────
    if request.video_info and request.video_info.ai_platform:
        signals.append({
            "name": "ai_video_platform",
            "delta": -20,
            "detail": f"Content is from AI video platform: {request.video_info.platform_name}",
        })
        structural_score = max(0, min(100, structural_score - 20))

    # ── Trend detection: check for previously flagged similar content ─
    flagged_similar = find_flagged_similar(request.text) if request.text else []
    if flagged_similar:
        signals.append({
            "name": "previously_flagged",
            "delta": -10,
            "detail": f"Similar content was previously flagged ({len(flagged_similar)} match(es))",
        })
        structural_score = max(0, min(100, structural_score - 10))

    # ── Fact-check score adjustments ──────────────────────────────────
    fc_delta = 0
    for fc in fact_checks:
        if fc.get("status") == "disputed":
            fc_delta -= 8
        elif fc.get("status") == "verified":
            fc_delta += 3

    # ── Combine scores (weighted) ─────────────────────────────────────
    llm_score = llm_result.get("trust_score", 50)
    combined_score = int(LLM_WEIGHT * llm_score + STRUCTURAL_WEIGHT * structural_score)
    combined_score = max(0, min(100, combined_score + fc_delta))

    all_evidence = list(llm_result.get("evidence", []))

    if flagged_similar:
        all_evidence.append(
            f"Similar content was previously flagged as suspicious ({len(flagged_similar)} time(s))."
        )

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
    }
    try:
        store_analysis_result(
            "page_scan", combined[:500], result_dict,
            fingerprint=fingerprint, url=request.url,
        )
    except Exception as exc:
        logger.warning("Storage failed: %s", exc)

    if request.url:
        try:
            update_domain_stats(request.url, combined_score, llm_result.get("verdict", "suspicious"))
        except Exception as exc:
            logger.warning("Domain stats update failed: %s", exc)

    fc_response = [FactCheckResult(**fc) for fc in fact_checks] if fact_checks else None

    return AnalyzeResponse(
        trust_score=combined_score,
        verdict=llm_result.get("verdict", "suspicious"),
        explanation=llm_result.get("explanation", ""),
        evidence=all_evidence,
        source_info=source_info,
        structural_signals=signals,
        fact_checks=fc_response,
        cached=False,
    )


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.4.0"}


# --------------- legacy per-type endpoints (direct API usage) ---------------

@app.post("/analyze/text")
async def analyze_text(content: str = Form(...)):
    result = text_analyzer.analyze(content)
    store_analysis_result("text", content, result)
    return result


@app.post("/analyze/image")
async def analyze_image(file: UploadFile = File(...)):
    result = await image_analyzer.analyze(file)
    store_analysis_result("image", file.filename, result)
    return result


@app.post("/analyze/pdf")
async def analyze_pdf(file: UploadFile = File(...)):
    result = await pdf_analyzer.analyze(file)
    store_analysis_result("pdf", file.filename, result)
    return result


@app.post("/analyze/video")
async def analyze_video(file: UploadFile = File(...)):
    result = await video_analyzer.analyze(file)
    store_analysis_result("video", file.filename, result)
    return result


@app.post("/analyze/url")
async def analyze_url(url: str = Form(...)):
    result = await url_analyzer.analyze(url)
    store_analysis_result("url", url, result)
    return result


@app.get("/models/info")
async def get_model_info():
    return {
        "text_model": {"id": TEXT_MODEL_ID, "max_tokens": DEFAULT_MAX_TOKENS},
        "multimodal_model": {"id": MULTIMODAL_MODEL_ID, "max_tokens": max(DEFAULT_MAX_TOKENS, 800)},
        "scoring": {"llm_weight": LLM_WEIGHT, "structural_weight": STRUCTURAL_WEIGHT},
        "temperature": DEFAULT_TEMPERATURE,
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
