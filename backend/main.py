from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from analyzers import text_analyzer, image_analyzer, pdf_analyzer, video_analyzer, url_analyzer
from elastic_utils import store_analysis_result, find_by_fingerprint, find_flagged_similar
from db import (store_image_scan, find_image_scan, add_community_flag,
                get_flag_count, has_user_flagged, count_scans_for_fingerprint)
from llm_utils import get_structured_analysis, get_image_verification
from scoring import compute_structural_score
from fingerprinting import compute_fingerprint
from trust_graph import update_domain_stats, compute_domain_trust_signal
from fact_checker import verify_claims as _verify_claims, verify_image_claim as _verify_image_claim, is_available as factcheck_available
from config import TEXT_MODEL_ID, MULTIMODAL_MODEL_ID, DEFAULT_MAX_TOKENS, DEFAULT_TEMPERATURE
import json
import re
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


class AnalyzeResponse(BaseModel):
    trust_score: int
    verdict: str
    explanation: str
    evidence: list[str]
    source_info: Optional[SourceInfo] = None
    structural_signals: Optional[list[dict]] = None
    fact_checks: Optional[list[FactCheckResult]] = None
    cached: Optional[bool] = None
    community_flags: Optional[int] = None
    community_scans: Optional[int] = None
    fingerprint: Optional[str] = None


class FlagRequest(BaseModel):
    fingerprint: str
    user_id: str
    reason: Optional[str] = None


class FlagResponse(BaseModel):
    success: bool
    flag_count: int
    already_flagged: bool = False


class ImageVerifyRequest(BaseModel):
    image_url: str
    page_url: Optional[str] = None
    page_text: Optional[str] = None
    social_context: Optional[dict] = None
    user_id: Optional[str] = None


class ImageVerifyResponse(BaseModel):
    authenticity_score: int
    verdict: str
    explanation: str
    evidence: list[str]
    claim_analysis: Optional[list[FactCheckResult]] = None


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
    import requests as req
    from io import BytesIO

    try:
        resp = req.get(url, timeout=10, stream=True, headers={
            "User-Agent": "FactScope/1.0",
        })
        if resp.status_code != 200:
            logger.warning("Image fetch failed: %d", resp.status_code)
            return None, None

        content_type = resp.headers.get("content-type", "image/jpeg")
        if not content_type.startswith("image/"):
            return None, None

        raw = resp.content
        if len(raw) > 10_000_000:
            logger.warning("Image too large: %d bytes", len(raw))
            return None, None

        try:
            from PIL import Image
            img = Image.open(BytesIO(raw))
            if img.mode == "RGBA":
                img = img.convert("RGB")

            w, h = img.size
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

    except Exception as exc:
        logger.warning("Image fetch error: %s", exc)
        return None, None


@app.post("/analyze/verify-image", response_model=ImageVerifyResponse)
async def verify_image(request: ImageVerifyRequest):
    """Verify an image for AI generation, manipulation, or misuse."""

    cached = find_image_scan(request.image_url)
    if cached:
        return ImageVerifyResponse(
            authenticity_score=cached.get("authenticity_score", 50),
            verdict=cached.get("verdict", "uncertain"),
            explanation=cached.get("explanation", ""),
            evidence=cached.get("evidence", []),
            claim_analysis=[FactCheckResult(**c) for c in cached["claim_analysis"]]
            if cached.get("claim_analysis") else None,
        )

    image_data, media_type = _fetch_and_resize_image(request.image_url)
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
    result = get_image_verification(image_data, media_type, context, bottom_crop=bottom_crop)

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

    if caption and len(caption.strip()) >= 10:
        try:
            fc = _verify_image_claim(caption)
            if fc:
                claim_results = [FactCheckResult(**c) for c in fc]
        except Exception as exc:
            logger.warning("Image claim verification failed: %s", exc)

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

        if not image_is_fake:
            corr_boost = min(25, best_sc * 5)
            final_score = min(100, final_score + corr_boost)

            if has_verified:
                final_score = min(100, final_score + 15)

        if has_dispute:
            final_score = max(0, final_score - 25)

        if best_sc >= 2 and source_names:
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

    response = ImageVerifyResponse(
        authenticity_score=final_score,
        verdict=final_verdict,
        explanation=final_explanation,
        evidence=result["evidence"],
        claim_analysis=claim_results,
    )

    try:
        store_image_scan(request.image_url, {
            "authenticity_score": final_score,
            "verdict": final_verdict,
            "explanation": final_explanation,
            "evidence": result["evidence"],
            "claim_analysis": [c.model_dump() for c in claim_results] if claim_results else None,
        }, user_id=request.user_id)
    except Exception as exc:
        logger.warning("Image scan storage failed: %s", exc)

    return response


@app.post("/flag", response_model=FlagResponse)
async def flag_content(request: FlagRequest):
    """Flag content as misinformation."""
    if has_user_flagged(request.fingerprint, request.user_id):
        count = get_flag_count(request.fingerprint)
        return FlagResponse(success=True, flag_count=count, already_flagged=True)

    added = add_community_flag(request.fingerprint, request.user_id, request.reason)
    count = get_flag_count(request.fingerprint)
    return FlagResponse(success=added, flag_count=count)


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_page(request: AnalyzeRequest):
    """Unified endpoint for the browser extension."""

    # ── Fingerprint check (instant cache) ─────────────────────────────
    fp_input = ""
    if request.title:
        fp_input += request.title + "\n"
    if request.text:
        fp_input += request.text
    fingerprint = compute_fingerprint(fp_input) if fp_input else None

    if fingerprint:
        cached = find_by_fingerprint(fingerprint)
        if cached:
            logger.info("Returning cached result for fingerprint %s", fingerprint[:16])

            fc_response = None
            if cached.get("judgement"):
                try:
                    fc_data = json.loads(cached["judgement"])
                    fc_response = [FactCheckResult(**fc) for fc in fc_data] if fc_data else None
                except (json.JSONDecodeError, TypeError):
                    pass

            comm_flags = get_flag_count(fingerprint)
            comm_scans = count_scans_for_fingerprint(fingerprint)
            return AnalyzeResponse(
                trust_score=cached.get("trust_score", 50),
                verdict=cached.get("verdict", "suspicious"),
                explanation=cached.get("explanation", ""),
                evidence=cached.get("evidence", []),
                cached=True,
                fact_checks=fc_response,
                community_flags=comm_flags if comm_flags > 0 else None,
                community_scans=comm_scans if comm_scans > 1 else None,
                fingerprint=fingerprint,
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
        "judgement": json.dumps(fact_checks) if fact_checks else None,
    }
    try:
        store_analysis_result(
            "page_scan", combined[:500], result_dict,
            fingerprint=fingerprint, url=request.url,
            user_id=request.user_id,
        )
    except Exception as exc:
        logger.warning("Storage failed: %s", exc)

    if request.url:
        try:
            update_domain_stats(request.url, combined_score, llm_result.get("verdict", "suspicious"))
        except Exception as exc:
            logger.warning("Domain stats update failed: %s", exc)

    fc_response = [FactCheckResult(**fc) for fc in fact_checks] if fact_checks else None

    comm_flags = get_flag_count(fingerprint) if fingerprint else 0
    comm_scans = count_scans_for_fingerprint(fingerprint) if fingerprint else 0

    return AnalyzeResponse(
        trust_score=combined_score,
        verdict=llm_result.get("verdict", "suspicious"),
        explanation=llm_result.get("explanation", ""),
        evidence=all_evidence,
        source_info=source_info,
        structural_signals=signals,
        fact_checks=fc_response,
        cached=False,
        community_flags=comm_flags if comm_flags > 0 else None,
        community_scans=comm_scans if comm_scans > 1 else None,
        fingerprint=fingerprint,
    )


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.4.0"}


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
        conn.close()
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
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT fingerprint, trust_score, verdict FROM scans WHERE fingerprint = ?",
            (fp,),
        ).fetchone()
        all_fps = conn.execute(
            "SELECT fingerprint FROM scans ORDER BY timestamp DESC LIMIT 5"
        ).fetchall()
        conn.close()
        return {
            "query_hit": row is not None,
            "result": dict(row) if row else None,
            "stored_fingerprints": [dict(r)["fingerprint"][:20] for r in all_fps],
        }
    except Exception as exc:
        conn.close()
        return {"error": str(exc)}


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
    from config import PORT, ENVIRONMENT
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        reload=(ENVIRONMENT == "development"),
    )
