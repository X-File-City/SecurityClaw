"""
core/rag_engine.py — Retrieval-Augmented Generation engine.

Provides:
  - Embedding text chunks via the LLM provider
  - Storing embeddings in the vector index
  - Retrieving top-k similar chunks for a query
  - Building a context string for LLM prompts
"""
from __future__ import annotations

import hashlib
import logging
import time
from typing import Optional

from core.config import Config
from core.db_connector import BaseDBConnector
from core.llm_provider import BaseLLMProvider

logger = logging.getLogger(__name__)


class RAGEngine:
    """
    Embeds, stores, and retrieves behavioral context chunks.

    Storage schema (per document in the vector index):
        {
            "id":        "<sha256 of text>",
            "text":      "<raw chunk>",
            "embedding": [<float>, ...],
            "category":  "<e.g. network_baseline>",
            "source":    "<skill or log name>",
            "timestamp": "<ISO8601>",
        }
    """

    def __init__(self, db: BaseDBConnector, llm: BaseLLMProvider) -> None:
        self.db = db
        self.llm = llm
        cfg = Config()
        self.index = cfg.get("db", "vector_index", default="securityclaw-vectors")
        self.top_k = cfg.get("rag", "top_k", default=5)
        self.threshold = cfg.get("rag", "similarity_threshold", default=0.65)
        
        # Ensure the vector index exists with proper knn_vector mapping
        self._ensure_vector_index()

    # ------------------------------------------------------------------
    # Index Management
    # ------------------------------------------------------------------

    def _ensure_vector_index(self) -> None:
        """
        Create the vector index with knn_vector mapping if it doesn't exist.
        For OpenSearch, this enables approximate k-NN search.
        
        If the index exists but has wrong dimensions, recreate it.
        """
        # Detect embedding dimension from LLM
        try:
            test_embed = self.llm.embed("test")
            embedding_dim = len(test_embed)
        except Exception as exc:
            logger.warning("Could not detect embedding dimension: %s", exc)
            embedding_dim = 384

        try:
            # Check if index exists and verify dimensions
            if hasattr(self.db, '_client'):
                client = self.db._client
                if client.indices.exists(index=self.index):
                    # Get current mapping to check dimension
                    mapping = client.indices.get_mapping(index=self.index)
                    current_dim = mapping.get(self.index, {}).get('mappings', {}).get('properties', {}).get('embedding', {}).get('dimension')
                    
                    if current_dim and current_dim != embedding_dim:
                        logger.warning(
                            "Vector index dimension mismatch: index=%d, embedding=%d. Recreating index.",
                            current_dim, embedding_dim
                        )
                        try:
                            client.indices.delete(index=self.index)
                            logger.info("Deleted old vector index: %s", self.index)
                        except Exception as e:
                            logger.warning("Could not delete index: %s", e)
            
            # Create/verify index with correct dimensions
            if hasattr(self.db, 'ensure_vector_index'):
                self.db.ensure_vector_index(self.index, dims=embedding_dim)
            else:
                # Fallback: use ensure_index with manual mappings
                mappings = {
                    "properties": {
                        "text": {"type": "text"},
                        "embedding": {
                            "type": "knn_vector",
                            "dimension": embedding_dim,
                        },
                        "category": {"type": "keyword"},
                        "source": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                    }
                }
                self.db.ensure_index(self.index, mappings)
            logger.info("Vector index '%s' ready (dim=%d)", self.index, embedding_dim)
        except Exception as exc:
            logger.error("Could not ensure vector index: %s", exc)

    # ------------------------------------------------------------------

    def store(self, text: str, category: str = "general", source: str = "unknown", metadata: dict = None) -> str:
        """
        Embed `text` and upsert into the vector index.
        
        Args:
            text: Text content to embed and store
            category: Document category/type
            source: Source skill/system that created document
            metadata: Optional dict with additional fields (e.g., identifier, network, etc.)
        
        Returns the document ID.
        """
        if not text or not text.strip():
            logger.warning("Skipping empty text for storage")
            return ""

        doc_id = hashlib.sha256(text.encode()).hexdigest()[:32]
        
        # Generate embedding
        embedding = self.llm.embed(text)
        if not embedding or len(embedding) == 0:
            logger.error("Failed to generate embedding for text: %s", text[:80])
            raise ValueError("Embedding generation returned empty result")
        
        doc = {
            "text": text,
            "embedding": embedding,
            "category": category,
            "source": source,
            "timestamp": _iso_now(),
        }
        
        # Add optional metadata fields
        if metadata:
            doc.update(metadata)
        
        self.db.index_document(self.index, doc_id, doc)
        logger.debug("Stored RAG chunk: %s (category=%s, dims=%d)", doc_id[:8], category, len(embedding))
        return doc_id

    def bulk_store(
        self,
        chunks: list[str],
        category: str = "general",
        source: str = "unknown",
        metadata: dict = None,
    ) -> list[str]:
        """Embed and store multiple chunks, returns list of IDs."""
        ids = []
        for chunk in chunks:
            try:
                ids.append(self.store(chunk, category=category, source=source, metadata=metadata))
            except Exception as exc:
                logger.error("Failed to store chunk: %s", exc)
        return ids

    # ------------------------------------------------------------------
    # Retrieve
    # ------------------------------------------------------------------

    def retrieve(
        self,
        query: str,
        k: Optional[int] = None,
        category: Optional[str] = None,
    ) -> list[dict]:
        """
        Embed `query` and return the top-k most similar stored chunks.
        """
        k = k or self.top_k
        try:
            query_vec = self.llm.embed(query)
        except Exception as exc:
            logger.error("Embed for retrieve failed: %s", exc)
            return []

        filters = None
        if category:
            filters = {"term": {"category": category}}

        hits = self.db.knn_search(
            index=self.index,
            vector=query_vec,
            k=k,
            filters=filters,
        )
        # Filter by similarity threshold (score is typically distance-based;
        # higher is more similar in cosine/dot-product spaces)
        return hits

    def build_context_string(
        self,
        query: str,
        k: Optional[int] = None,
        category: Optional[str] = None,
        prefix: str = "### Relevant Behavioral Context\n",
    ) -> str:
        """
        Retrieve top-k chunks and format them as a numbered context block
        ready to inject into an LLM prompt.
        """
        hits = self.retrieve(query, k=k, category=category)
        if not hits:
            return prefix + "_No relevant context found._\n"

        lines = [prefix]
        for i, hit in enumerate(hits, 1):
            text = hit.get("text", "")
            src = hit.get("source", "?")
            cat = hit.get("category", "?")
            lines.append(f"{i}. [{cat}/{src}] {text}")

        return "\n".join(lines) + "\n"


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
