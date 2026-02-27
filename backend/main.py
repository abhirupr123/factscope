from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from analyzers import text_analyzer, image_analyzer, pdf_analyzer, video_analyzer, url_analyzer
from elastic_utils import store_analysis_result
from llm_utils import get_structured_analysis
from config import TEXT_MODEL_ID, MULTIMODAL_MODEL_ID, DEFAULT_MAX_TOKENS, DEFAULT_TEMPERATURE
import uvicorn
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="FactScope API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    text: Optional[str] = None
    links: Optional[list[str]] = None
    sample_img: Optional[str] = None


class AnalyzeResponse(BaseModel):
    trust_score: int
    verdict: str
    explanation: str
    evidence: list[str]


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_page(request: AnalyzeRequest):
    """Unified endpoint for the browser extension.
    Accepts page content (text, links, image URL) and returns a structured verdict.
    """
    content_parts = []

    if request.text:
        content_parts.append(f"Page text content:\n{request.text[:3000]}")

    if request.links:
        links_summary = "\n".join(request.links[:10])
        content_parts.append(f"Links found on page:\n{links_summary}")

    if request.sample_img:
        content_parts.append(f"Image URL found on page: {request.sample_img}")

    combined = "\n\n---\n\n".join(content_parts)

    if not combined.strip():
        return AnalyzeResponse(
            trust_score=50,
            verdict="unknown",
            explanation="No content was provided for analysis.",
            evidence=["No text, links, or images were extracted from the page."],
        )

    result = get_structured_analysis(combined)

    try:
        store_analysis_result("page_scan", combined[:500], result)
    except Exception as exc:
        logger.warning("Elasticsearch storage failed: %s", exc)

    return AnalyzeResponse(**result)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.2.0"}


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
        "text_model": {
            "id": TEXT_MODEL_ID,
            "description": "Used for text-only analysis (faster, cost-effective)",
            "max_tokens": DEFAULT_MAX_TOKENS,
        },
        "multimodal_model": {
            "id": MULTIMODAL_MODEL_ID,
            "description": "Used for multimedia content analysis",
            "max_tokens": max(DEFAULT_MAX_TOKENS, 800),
        },
        "temperature": DEFAULT_TEMPERATURE,
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
