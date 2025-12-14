from elasticsearch import Elasticsearch
from config import ELASTIC_URL, ELASTIC_INDEX, ELASTIC_API_KEY

es = Elasticsearch(ELASTIC_URL, api_key=ELASTIC_API_KEY)

def store_analysis_result(doc_type, source, result):
    doc = {
        "doc_type": doc_type,
        "source": source,
        "judgement": result["judgement"] if result.get("judgement") else "Unknown"
    }
    es.index(index=ELASTIC_INDEX, body=doc)
