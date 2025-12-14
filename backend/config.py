import os
from pathlib import Path


def _load_local_env():
    """
    Load environment variables from a local env file if it exists.
    This avoids hardcoding secrets in source while keeping local dev simple.
    """
    for name in ("secrets.env", ".env.local"):
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

ELASTIC_URL = os.getenv("ELASTIC_URL")
ELASTIC_INDEX = os.getenv("ELASTIC_INDEX", "fake_content")
AWS_REGION = os.getenv("AWS_REGION", "us-west-2")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY")

# Model Configuration
# Text-only analysis model (faster, cheaper)
TEXT_MODEL_ID = os.getenv("TEXT_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")

# Multimodal analysis model (supports images, more capable)
MULTIMODAL_MODEL_ID = os.getenv("MULTIMODAL_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0")

# Model parameters
DEFAULT_MAX_TOKENS = int(os.getenv("DEFAULT_MAX_TOKENS", "500"))
DEFAULT_TEMPERATURE = float(os.getenv("DEFAULT_TEMPERATURE", "0.2"))
