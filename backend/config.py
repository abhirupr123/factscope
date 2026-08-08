import os
from pathlib import Path


def _load_local_env():
    """Load environment variables from a local env file if it exists."""
    for name in ("secrets.env", ".env.local", ".env"):
        env_file = Path(__file__).parent / name
        if not env_file.exists():
            continue
        for line in env_file.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


_load_local_env()

# ── LLM Provider ─────────────────────────────────────────────────────────────
# Supported: "gemini" | "openai" | "bedrock"
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini")

# Gemini (default)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemma-4-31b-it")
GEMINI_FALLBACK_MODEL = os.getenv("GEMINI_FALLBACK_MODEL", "gemma-4-26b-a4b-it")

# OpenAI
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# AWS Bedrock
AWS_REGION = os.getenv("AWS_REGION", "us-west-2")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY")
TEXT_MODEL_ID = os.getenv("TEXT_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")
MULTIMODAL_MODEL_ID = os.getenv("MULTIMODAL_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0")

# Light model for flag validation (separate from main analysis model)
FLAG_VALIDATION_MODEL = os.getenv("FLAG_VALIDATION_MODEL", "gemma-4-26b-a4b-it")

# ── Shared model parameters ──────────────────────────────────────────────────
DEFAULT_MAX_TOKENS = int(os.getenv("DEFAULT_MAX_TOKENS", "500"))
DEFAULT_TEMPERATURE = float(os.getenv("DEFAULT_TEMPERATURE", "0.2"))

# ── Google Fact Check API ─────────────────────────────────────────────────────
GOOGLE_FACTCHECK_API_KEY = os.getenv("GOOGLE_FACTCHECK_API_KEY")

# ── Turso Database (cloud libSQL — https://turso.tech) ───────────────────────
TURSO_DATABASE_URL = os.getenv("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = os.getenv("TURSO_AUTH_TOKEN")

# ── Rate limiting / tiers ─────────────────────────────────────────────────────
SCAN_LIMITS = {"free": 10, "standard": 50, "premium": 200}
ADMIN_USER_IDS = set(
    uid.strip() for uid in os.getenv("ADMIN_USER_IDS", "").split(",") if uid.strip()
)

# ── Deployment ───────────────────────────────────────────────────────────────
PORT = int(os.getenv("PORT", "8000"))
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

# Security controls
MAX_REQUEST_BYTES = int(os.getenv("MAX_REQUEST_BYTES", "2097152"))
CORS_ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ALLOWED_ORIGINS",
        (
            "chrome-extension://cmmkbibkldbifbiefgebcecdakljejjd,"
            "http://localhost:8000,http://127.0.0.1:8000"
        ),
    ).split(",")
    if origin.strip()
]

# Anonymous installation sessions and cost protection
SESSION_SIGNING_SECRET = os.getenv("SESSION_SIGNING_SECRET", "")
if ENVIRONMENT == "production" and len(SESSION_SIGNING_SECRET) < 32:
    raise RuntimeError("SESSION_SIGNING_SECRET must be at least 32 characters in production")
if not SESSION_SIGNING_SECRET:
    SESSION_SIGNING_SECRET = "factscope-local-development-session-key"

SESSION_TTL_DAYS = int(os.getenv("SESSION_TTL_DAYS", "180"))
SESSION_MINTS_PER_HOUR = int(os.getenv("SESSION_MINTS_PER_HOUR", "10"))
API_REQUESTS_PER_MINUTE = int(os.getenv("API_REQUESTS_PER_MINUTE", "60"))
ANALYSIS_REQUESTS_PER_MINUTE = int(os.getenv("ANALYSIS_REQUESTS_PER_MINUTE", "5"))
CACHE_HITS_PER_HOUR = int(os.getenv("CACHE_HITS_PER_HOUR", "120"))
ANALYSIS_VERSION = os.getenv("ANALYSIS_VERSION", "4h-1")
ANALYSIS_CACHE_MAX_AGE_HOURS = min(720, max(1, int(os.getenv("ANALYSIS_CACHE_MAX_AGE_HOURS", "24"))))
MAX_CONCURRENT_ANALYSES = int(os.getenv("MAX_CONCURRENT_ANALYSES", "3"))
ANALYSIS_TIMEOUT_SECONDS = float(os.getenv("ANALYSIS_TIMEOUT_SECONDS", "100"))
IMAGE_ANALYSIS_TIMEOUT_SECONDS = float(os.getenv("IMAGE_ANALYSIS_TIMEOUT_SECONDS", "100"))
PROVIDER_HTTP_TIMEOUT_SECONDS = float(os.getenv("PROVIDER_HTTP_TIMEOUT_SECONDS", "30"))
FACTCHECK_TIMEOUT_SECONDS = float(os.getenv("FACTCHECK_TIMEOUT_SECONDS", "20"))
DAILY_LLM_CALL_LIMIT = int(os.getenv("DAILY_LLM_CALL_LIMIT", "500"))
LLM_ESTIMATED_COST_USD = float(os.getenv("LLM_ESTIMATED_COST_USD", "0.002"))
RAW_SCAN_RETENTION_DAYS = min(30, max(1, int(os.getenv("RAW_SCAN_RETENTION_DAYS", "30"))))
TELEMETRY_RETENTION_DAYS = min(30, max(1, int(os.getenv("TELEMETRY_RETENTION_DAYS", "30"))))
RETENTION_CLEANUP_INTERVAL_SECONDS = int(os.getenv("RETENTION_CLEANUP_INTERVAL_SECONDS", "86400"))
