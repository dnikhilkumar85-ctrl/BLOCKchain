from .embedding import load_embedding_model, create_embeddings
import numpy as np
import logging

logger = logging.getLogger(__name__)

class RAGSystem:
    """
    Self-initializing RAG system for cybersecurity log retrieval.
    Can be initialized with pre-built documents + vector_store,
    or lazily rebuilt from DB logs via rebuild().
    """
    def __init__(self, documents=None, vector_store=None):
        self.documents = documents or []
        self.vector_store = vector_store
        self._model = None  # Lazy load embedding model

    @property
    def model(self):
        if self._model is None:
            self._model = load_embedding_model()
        return self._model

    def rebuild(self, documents: list):
        """
        Rebuild the FAISS vector store from a fresh list of text documents.
        Call this whenever new logs are added to the DB.
        """
        if not documents:
            logger.warning("RAGSystem.rebuild(): No documents provided — skipping.")
            return False
        try:
            from .vector_store import VectorStore
            self.documents = documents
            embeddings = create_embeddings(documents)
            self.vector_store = VectorStore(embeddings)
            logger.info(f"RAGSystem rebuilt with {len(documents)} documents.")
            return True
        except Exception as e:
            logger.error(f"RAGSystem.rebuild() failed: {e}")
            return False

    def retrieve(self, query: str, k: int = 3) -> list:
        """
        Retrieve top-k most relevant documents for the query.
        Returns empty list if RAG is not initialized.
        """
        if not self.documents or self.vector_store is None:
            logger.warning("RAGSystem.retrieve(): Not initialized — returning empty.")
            return []
        try:
            query_embedding = self.model.encode([query])
            indices = self.vector_store.search(query_embedding, k)
            return [self.documents[i] for i in indices if i < len(self.documents)]
        except Exception as e:
            logger.error(f"RAGSystem.retrieve() failed: {e}")
            return []

    @property
    def is_ready(self) -> bool:
        return bool(self.documents) and self.vector_store is not None
