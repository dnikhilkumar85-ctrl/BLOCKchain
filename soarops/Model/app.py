from flask import Flask, request, jsonify
import logging
import os

from database.query_handler import extract_ip, handle_ip_query, handle_sql_query
from Rag.retriever import RAGSystem
from Rag.preprocess import load_csv, convert_to_documents
from Rag.embedding import create_embeddings
from Rag.vector_store import VectorStore
from Rag.prompt_template import build_prompt
from llm.ollama_client import generate_response

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- Initialize RAG properly ---
RAG_DATA_PATH = os.environ.get("RAG_CSV_PATH", "data/network_logs.csv")

def init_rag() -> RAGSystem:
    """Load documents from CSV and build RAG system with FAISS index."""
    rag = RAGSystem()
    if not os.path.exists(RAG_DATA_PATH):
        logger.warning(
            f"RAG CSV not found at '{RAG_DATA_PATH}'. "
            "RAG will be disabled until data is provided. "
            "Set RAG_CSV_PATH env var to point to your network_logs.csv."
        )
        return rag  # Returns empty/disabled RAG — won't crash

    logger.info(f"Loading RAG documents from {RAG_DATA_PATH}...")
    df = load_csv(RAG_DATA_PATH)
    documents = convert_to_documents(df)
    embeddings = create_embeddings(documents)
    vector_store = VectorStore(embeddings)
    rag.rebuild(documents)   # Properly initializes via rebuild()
    logger.info(f"RAG ready with {len(documents)} documents.")
    return rag

rag = init_rag()


def classify_query(query):
    keywords = ["count", "how many", "total"]
    for word in keywords:
        if word in query.lower():
            return "sql"
    return "rag"

@app.route("/chat", methods=["POST"])
def chat():
    user_query = request.json.get("query", "")
    if not user_query:
        return jsonify({"error": "Missing 'query' field"}), 400

    ip = extract_ip(user_query)

    # IP-Specific query
    if ip:
        incidents, blocked = handle_ip_query(ip)
        context = f"IP: {ip}\nIncidents: {incidents}\nBlocked Status: {blocked if blocked else 'Not Blocked'}"
        prompt = build_prompt(context, user_query)
        return jsonify({"response": generate_response(prompt)})

    # SQL aggregate query
    if classify_query(user_query) == "sql":
        return jsonify({"response": handle_sql_query()})

    # RAG Query
    if rag.is_ready:
        docs = rag.retrieve(user_query)
        context = "\n".join(docs)
    else:
        context = "No network log data available for retrieval."

    prompt = build_prompt(context, user_query)
    return jsonify({"response": generate_response(prompt)})

if __name__ == "__main__":
    app.run(debug=True)
