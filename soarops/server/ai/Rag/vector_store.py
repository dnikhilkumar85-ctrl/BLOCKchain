import numpy as np
import logging

logger = logging.getLogger(__name__)

try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    logger.error("faiss-cpu not installed. Run: py -m pip install faiss-cpu")
    FAISS_AVAILABLE = False

class VectorStore:
    """FAISS-backed vector store for similarity search."""

    def __init__(self, embeddings):
        if not FAISS_AVAILABLE:
            raise RuntimeError("faiss-cpu is required. Install with: py -m pip install faiss-cpu")
        # Cast to float32 — FAISS requirement
        embeddings = np.array(embeddings, dtype=np.float32)
        self.dimension = embeddings.shape[1]
        self.index = faiss.IndexFlatL2(self.dimension)
        self.index.add(embeddings)
        logger.info(f"VectorStore created with {len(embeddings)} vectors (dim={self.dimension})")

    def search(self, query_embedding, k=3):
        # Cast to float32 — FAISS requirement
        query_embedding = np.array(query_embedding, dtype=np.float32)
        k = min(k, self.index.ntotal)  # Can't retrieve more than what's stored
        if k == 0:
            return []
        D, I = self.index.search(query_embedding, k)
        return I[0].tolist()
