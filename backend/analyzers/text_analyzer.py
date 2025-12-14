from llm_utils import get_llm_judgement

def analyze(content: str):
    # Simple pipeline: send to LLM
    judgement = get_llm_judgement(content)
    return {"type": "text", "content": content, "judgement": judgement}
