from fastapi import FastAPI, UploadFile, File, Form
from analyzers import text_analyzer, image_analyzer, pdf_analyzer, video_analyzer, url_analyzer
from elastic_utils import store_analysis_result
from config import TEXT_MODEL_ID, MULTIMODAL_MODEL_ID, DEFAULT_MAX_TOKENS, DEFAULT_TEMPERATURE
import uvicorn

app = FastAPI(title="Fake Content Detection API")

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
    """Get information about the AI models used for different content types"""
    return {
        "text_model": {
            "id": TEXT_MODEL_ID,
            "description": "Used for text-only analysis (faster, cost-effective)",
            "capabilities": ["text analysis", "spam detection", "fake news detection"],
            "max_tokens": DEFAULT_MAX_TOKENS
        },
        "multimodal_model": {
            "id": MULTIMODAL_MODEL_ID,
            "description": "Used for multimedia content analysis (images, videos with text)",
            "capabilities": ["text analysis", "image analysis", "visual content detection", "deepfake detection"],
            "max_tokens": max(DEFAULT_MAX_TOKENS, 800)
        },
        "selection_logic": "Automatically selects multimodal model when media content is detected, otherwise uses text model",
        "temperature": DEFAULT_TEMPERATURE
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
