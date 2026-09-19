import requests
import json
import logging

logger = logging.getLogger(__name__)
OLLAMA_URL = "http://localhost:11434"


def check_ollama_available() -> bool:
    """Returns True if the Ollama server is reachable and running."""
    try:
        resp = requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
        return resp.status_code == 200
    except Exception:
        return False


def generate_response(prompt: str):
    """Stream response tokens from Ollama llama3 model."""
    with requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={
            "model": "llama3",
            "prompt": prompt,
            "temperature": 0.1,
            "stream": True
        },
        stream=True,
        timeout=60
    ) as response:
        for line in response.iter_lines():
            if line:
                try:
                    json_response = json.loads(line)
                    if "response" in json_response:
                        yield json_response["response"]
                except json.JSONDecodeError:
                    continue
