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
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

# OpenAI
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# AWS Bedrock
AWS_REGION = os.getenv("AWS_REGION", "us-west-2")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY")
TEXT_MODEL_ID = os.getenv("TEXT_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")
MULTIMODAL_MODEL_ID = os.getenv("MULTIMODAL_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0")

# ── Shared model parameters ──────────────────────────────────────────────────
DEFAULT_MAX_TOKENS = int(os.getenv("DEFAULT_MAX_TOKENS", "500"))
DEFAULT_TEMPERATURE = float(os.getenv("DEFAULT_TEMPERATURE", "0.2"))

# ── Google Fact Check API ─────────────────────────────────────────────────────
GOOGLE_FACTCHECK_API_KEY = os.getenv("GOOGLE_FACTCHECK_API_KEY")

# ── Turso Database (cloud libSQL — https://turso.tech) ───────────────────────
TURSO_DATABASE_URL = os.getenv("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = os.getenv("TURSO_AUTH_TOKEN")

# ── Deployment ───────────────────────────────────────────────────────────────
PORT = int(os.getenv("PORT", "8000"))
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
