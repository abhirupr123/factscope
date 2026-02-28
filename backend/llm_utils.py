import json
import re
import base64
import logging
from fastapi import UploadFile
from config import (
    LLM_PROVIDER, DEFAULT_MAX_TOKENS, DEFAULT_TEMPERATURE,
    GEMINI_API_KEY, GEMINI_MODEL,
    OPENAI_API_KEY, OPENAI_MODEL,
    AWS_REGION, AWS_ACCESS_KEY, AWS_SECRET_KEY,
    TEXT_MODEL_ID, MULTIMODAL_MODEL_ID,
)

logger = logging.getLogger(__name__)

STRUCTURED_SYSTEM_PROMPT = """\
You are FactScope, a content-authenticity analyst.

Respond with ONLY valid JSON. No markdown, no backticks, no extra text.
{
  "trust_score": <integer 0-100>,
  "verdict": "<authentic|misleading|ai_generated|spam|phishing|suspicious>",
  "explanation": "<MAX 2 short sentences. Be direct and insightful.>",
  "evidence": ["<short point 1>", "<short point 2>"]
}

Scoring: 80-100 authentic, 60-79 minor concerns, 40-59 mixed, 20-39 red flags, 0-19 clearly fake/spam.

Rules:
- Keep explanation under 40 words and each evidence item under 15 words. Max 3 evidence items.
- For well-known reputable sites (news outlets, Wikipedia, IMDb, government sites, etc.), be brief and confident. Do NOT over-explain why a trusted source looks trusted — that is obvious to the user.
- Focus evidence on things the user might NOT already know. Never state the obvious (e.g. don't say "this is IMDb" when the user is on IMDb).
- Be most detailed when content is genuinely suspicious, misleading, or AI-generated — that is where your analysis adds real value."""

FREETEXT_SYSTEM_PROMPT = """\
You are FactScope, an expert content-authenticity analyst. \
Analyze the provided content and explain in simple, plain English \
whether it appears to be fake, spam, AI-generated, phishing, or authentic — and why. \
Be concise (3-5 sentences). Mention specific red flags or trust signals you observe."""


# ═══════════════════════════════════════════════════════════════════════════════
# Provider clients (lazy-initialized to avoid import errors for unused providers)
# ═══════════════════════════════════════════════════════════════════════════════

_openai_client = None
_bedrock_client = None


def _get_openai_client():
    global _openai_client
    if _openai_client is None:
        from openai import OpenAI
        _openai_client = OpenAI(api_key=OPENAI_API_KEY)
    return _openai_client


def _get_bedrock_client():
    global _bedrock_client
    if _bedrock_client is None:
        import boto3
        _bedrock_client = boto3.client(
            service_name="bedrock-runtime",
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
        )
    return _bedrock_client


# ═══════════════════════════════════════════════════════════════════════════════
# Core LLM call — routes to the configured provider
# ═══════════════════════════════════════════════════════════════════════════════

def _call_llm(
    system_prompt: str,
    user_content: str,
    media_data: bytes = None,
    media_type: str = None,
    min_tokens: int = 0,
) -> str:
    """Send a prompt to the configured LLM provider and return the raw text response.
    min_tokens ensures the max_tokens sent to the provider is at least this value.
    """
    provider = LLM_PROVIDER
    max_tokens = max(DEFAULT_MAX_TOKENS, min_tokens)
    logger.info("LLM call via provider=%s has_media=%s max_tokens=%d", provider, media_data is not None, max_tokens)

    if provider == "gemini":
        return _call_gemini(system_prompt, user_content, media_data, media_type, max_tokens)
    elif provider == "openai":
        return _call_openai(system_prompt, user_content, media_data, media_type, max_tokens)
    elif provider == "bedrock":
        return _call_bedrock(system_prompt, user_content, media_data, media_type, max_tokens)
    else:
        raise ValueError(f"Unknown LLM_PROVIDER: {provider!r}. Use 'gemini', 'openai', or 'bedrock'.")


# ── Gemini ────────────────────────────────────────────────────────────────────

def _call_gemini(system_prompt, user_content, media_data, media_type, max_tokens):
    import google.generativeai as genai

    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(
        model_name=GEMINI_MODEL,
        system_instruction=system_prompt,
        generation_config=genai.GenerationConfig(
            temperature=DEFAULT_TEMPERATURE,
            max_output_tokens=max_tokens,
        ),
    )

    parts = [user_content]
    if media_data and media_type and media_type.startswith("image/"):
        parts.append({"mime_type": media_type, "data": media_data})

    response = model.generate_content(parts)
    return response.text


# ── OpenAI ────────────────────────────────────────────────────────────────────

def _call_openai(system_prompt, user_content, media_data, media_type, max_tokens):
    client = _get_openai_client()

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})

    if media_data and media_type and media_type.startswith("image/"):
        b64 = base64.b64encode(media_data).decode("utf-8")
        messages.append({
            "role": "user",
            "content": [
                {"type": "text", "text": user_content},
                {"type": "image_url", "image_url": {"url": f"data:{media_type};base64,{b64}"}},
            ],
        })
    else:
        messages.append({"role": "user", "content": user_content})

    resp = client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=messages,
        temperature=DEFAULT_TEMPERATURE,
        max_tokens=max_tokens,
    )
    return resp.choices[0].message.content


# ── AWS Bedrock (Claude) ─────────────────────────────────────────────────────

def _call_bedrock(system_prompt, user_content, media_data, media_type, max_tokens):
    client = _get_bedrock_client()

    message_content = [{"type": "text", "text": user_content}]

    if media_data and media_type and media_type.startswith("image/"):
        b64 = base64.b64encode(media_data).decode("utf-8")
        message_content.append({
            "type": "image",
            "source": {"type": "base64", "media_type": media_type, "data": b64},
        })

    has_media = media_data is not None and media_type is not None
    model_id = MULTIMODAL_MODEL_ID if has_media else TEXT_MODEL_ID
    if has_media:
        max_tokens = max(max_tokens, 800)

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "temperature": DEFAULT_TEMPERATURE,
        "system": system_prompt or "",
        "messages": [{"role": "user", "content": message_content}],
    })

    response = client.invoke_model(
        modelId=model_id, body=body,
        accept="application/json", contentType="application/json",
    )
    raw = json.loads(response["body"].read())
    if "content" in raw and raw["content"]:
        return raw["content"][0]["text"]
    return "No response from model."


# ═══════════════════════════════════════════════════════════════════════════════
# Public API — structured analysis (unified /analyze endpoint)
# ═══════════════════════════════════════════════════════════════════════════════

def get_structured_analysis(
    content: str,
    media_data: bytes = None,
    media_type: str = None,
) -> dict:
    """Return a dict with trust_score, verdict, explanation, evidence."""
    try:
        raw_text = _call_llm(
            STRUCTURED_SYSTEM_PROMPT, content, media_data, media_type,
            min_tokens=2048,
        )
        return _parse_structured_response(raw_text)
    except Exception as exc:
        logger.error("Structured analysis failed: %s", exc)
        return {
            "trust_score": 0,
            "verdict": "error",
            "explanation": f"Analysis could not be completed: {exc}",
            "evidence": [],
        }


def _parse_structured_response(raw_text: str) -> dict:
    """Parse LLM JSON response with robust fallback for truncated or malformed output."""
    # 1. Try direct parse
    for candidate in (raw_text, _extract_json_block(raw_text)):
        if candidate is None:
            continue
        try:
            return _validate_result(json.loads(candidate))
        except (json.JSONDecodeError, TypeError):
            continue

    # 2. Try to recover partial JSON (model ran out of tokens mid-response)
    recovered = _recover_partial_json(raw_text)
    if recovered:
        return recovered

    # 3. If the raw text looks like prose (not broken JSON), use it as the explanation
    clean = raw_text.strip().lstrip("{").strip()
    if len(clean) > 20 and not clean.startswith('"'):
        return {
            "trust_score": 50,
            "verdict": "suspicious",
            "explanation": clean[:500],
            "evidence": [],
        }

    # 4. Final fallback
    return {
        "trust_score": 50,
        "verdict": "suspicious",
        "explanation": "The page could not be fully analyzed. Try scanning again.",
        "evidence": [],
    }


def _extract_json_block(text: str):
    match = re.search(r"\{[\s\S]*\}", text)
    return match.group() if match else None


def _recover_partial_json(raw_text: str) -> dict | None:
    """Extract whatever fields we can from truncated JSON."""
    result = {}

    score_match = re.search(r'"trust_score"\s*:\s*(\d+)', raw_text)
    if score_match:
        result["trust_score"] = int(score_match.group(1))

    verdict_match = re.search(r'"verdict"\s*:\s*"([^"]*)"?', raw_text)
    if verdict_match:
        result["verdict"] = verdict_match.group(1).strip()

    explanation_match = re.search(r'"explanation"\s*:\s*"((?:[^"\\]|\\.)*)"?', raw_text)
    if explanation_match:
        result["explanation"] = explanation_match.group(1).strip()

    evidence_match = re.findall(r'"evidence"\s*:\s*\[(.*?)\]', raw_text, re.DOTALL)
    if evidence_match:
        items = re.findall(r'"((?:[^"\\]|\\.)*)"', evidence_match[0])
        result["evidence"] = items

    if "trust_score" in result or "explanation" in result:
        return _validate_result(result)

    return None


def _validate_result(result: dict) -> dict:
    trust_score = result.get("trust_score", 50)
    if not isinstance(trust_score, (int, float)):
        trust_score = 50
    trust_score = max(0, min(100, int(trust_score)))

    valid_verdicts = {
        "authentic", "misleading", "ai_generated",
        "spam", "phishing", "suspicious",
    }
    verdict = result.get("verdict", "suspicious")
    if verdict not in valid_verdicts:
        verdict = "suspicious"

    explanation = str(result.get("explanation", "No explanation available."))
    evidence = result.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = [str(evidence)]

    return {
        "trust_score": trust_score,
        "verdict": verdict,
        "explanation": explanation,
        "evidence": [str(e) for e in evidence],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Public API — free-text judgement (legacy per-type endpoints)
# ═══════════════════════════════════════════════════════════════════════════════

def get_llm_judgement(
    content: str = None,
    media_data: bytes = None,
    media_type: str = None,
) -> str:
    """Free-text LLM judgement for backward-compatible per-type endpoints."""
    # Validate image if provided
    if media_data and media_type:
        if media_type.startswith("image/"):
            supported = {"image/jpeg", "image/png", "image/gif", "image/webp"}
            if media_type not in supported:
                return f"Unsupported image format: {media_type}"
            if len(media_data) > 5 * 1024 * 1024:
                return "Image too large (5 MB limit)"
        elif not media_type.startswith("image/"):
            return f"Unsupported media type: {media_type}"

    user_msg = content or ""
    if not user_msg and not media_data:
        return "No content provided for analysis."

    if not user_msg and media_data:
        user_msg = "Analyze the attached image for signs of manipulation, AI generation, or inauthenticity."

    try:
        return _call_llm(FREETEXT_SYSTEM_PROMPT, user_msg, media_data, media_type)
    except Exception as exc:
        return f"Error during LLM analysis: {exc}"


async def get_llm_judgement_from_file(file: UploadFile, additional_text: str = None) -> str:
    """Helper to analyze UploadFile objects (used by image_analyzer)."""
    file_data = await file.read()
    await file.seek(0)
    content_type = file.content_type or "application/octet-stream"
    return get_llm_judgement(content=additional_text, media_data=file_data, media_type=content_type)
