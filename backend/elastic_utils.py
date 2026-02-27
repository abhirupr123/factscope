import logging
from datetime import datetime, timezone
from elasticsearch import Elasticsearch
from config import ELASTIC_URL, ELASTIC_INDEX, ELASTIC_API_KEY

logger = logging.getLogger(__name__)

es = None
try:
    if ELASTIC_URL and ELASTIC_API_KEY:
        es = Elasticsearch(ELASTIC_URL, api_key=ELASTIC_API_KEY)
        es.info()
        logger.info("Connected to Elasticsearch at %s", ELASTIC_URL)
except Exception as exc:
    logger.warning("Elasticsearch unavailable — results will not be stored: %s", exc)
    es = None


def store_analysis_result(doc_type: str, source, result):
    """Store an analysis result. Handles both legacy (judgement) and structured formats.
    Silently skips if Elasticsearch is not connected."""
    if es is None:
        return

    try:
        doc = {
            "doc_type": doc_type,
            "source": str(source)[:500],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if isinstance(result, dict):
            if "trust_score" in result:
                doc["trust_score"] = result["trust_score"]
                doc["verdict"] = result.get("verdict")
                doc["explanation"] = result.get("explanation")
                doc["evidence"] = result.get("evidence", [])
            if "judgement" in result:
                doc["judgement"] = result["judgement"]

        es.index(index=ELASTIC_INDEX, document=doc)
    except Exception as exc:
        logger.warning("Failed to store analysis result: %s", exc)
