from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    from pinecone import Pinecone, ServerlessSpec
    PINECONE_AVAILABLE = True
except ImportError:
    PINECONE_AVAILABLE = False

import google.generativeai as genai
from google.generativeai import embedding

from app.core.config import settings

logger = logging.getLogger(__name__)


class VectorStoreService:
    """
    Vector store service for managing Pinecone with two namespaces:
    - vulns_namespace: Raw vulnerability data from scans
    - kb_namespace: Static knowledge base + AI-generated summaries
    """
    
    def __init__(self):
        if not PINECONE_AVAILABLE:
            raise RuntimeError("pinecone-client not available. Install with: pip install pinecone-client")
        
        if not settings.pinecone_api_key:
            raise RuntimeError("PINECONE_API_KEY not configured in settings")
        
        # Initialize Pinecone
        self.pc = Pinecone(api_key=settings.pinecone_api_key)
        self.index_name = settings.pinecone_index
        self.vulns_namespace = settings.vulns_namespace
        self.kb_namespace = settings.kb_namespace
        
        # Get or create index
        self._ensure_index_exists()
        self.index = self.pc.Index(self.index_name)
        
        # Configure Gemini for embeddings (already configured in ai_service, but ensure it's set)
        if not settings.gemini_api_key:
            raise RuntimeError("GEMINI_API_KEY not configured in settings")
        genai.configure(api_key=settings.gemini_api_key)
        
        logger.info(f"VectorStoreService initialized with index: {self.index_name}")
        logger.info(f"Namespaces: {self.vulns_namespace}, {self.kb_namespace}")
    
    def _ensure_index_exists(self) -> None:
        """Ensure Pinecone index exists, create if it doesn't."""
        try:
            existing_indexes = [idx.name for idx in self.pc.list_indexes()]
            if self.index_name not in existing_indexes:
                logger.info(f"Creating Pinecone index: {self.index_name} with dimension {settings.vector_dimension}")
                self.pc.create_index(
                    name=self.index_name,
                    dimension=settings.vector_dimension,
                    metric="cosine",
                    spec=ServerlessSpec(
                        cloud="aws",
                        region=settings.pinecone_environment
                    )
                )
                logger.info(f"Index {self.index_name} created successfully")
            else:
                # Check if existing index dimension matches
                index_info = self.pc.describe_index(self.index_name)
                existing_dimension = index_info.dimension
                if existing_dimension != settings.vector_dimension:
                    error_msg = (
                        f"Index dimension mismatch! "
                        f"Existing index '{self.index_name}' has dimension {existing_dimension}, "
                        f"but config expects {settings.vector_dimension}. "
                        f"Please delete the index or update VECTOR_DIMENSION to {existing_dimension}."
                    )
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                logger.info(f"Index {self.index_name} already exists with dimension {existing_dimension}")
        except Exception as e:
            logger.error(f"Error ensuring index exists: {e}")
            raise
    
    def generate_embedding(self, text: str) -> List[float]:
        """
        Generate embedding using Gemini embedding model.
        """
        try:
            model = settings.embedding_model
            result = embedding.embed_content(
                model=model,
                content=text,
                task_type="RETRIEVAL_DOCUMENT"
            )
            return result["embedding"]
        except Exception as e:
            logger.error(f"Error generating embedding: {e}")
            raise RuntimeError(f"Failed to generate embedding: {e}")
    
    def generate_embeddings_batch(self, texts: List[str]) -> List[List[float]]:
        """
        Generate embeddings for multiple texts using Gemini.
        """
        try:
            model = settings.embedding_model
            results = embedding.embed_content(
                model=model,
                content=texts,
                task_type="RETRIEVAL_DOCUMENT"
            )
            # For batch, embed_content returns {"embedding": [[float, ...], [float, ...], ...]}
            if isinstance(results, dict) and "embedding" in results:
                embeddings = results["embedding"]
                # Ensure it's a list of lists
                if embeddings and isinstance(embeddings[0], list):
                    return embeddings
                else:
                    # Single embedding wrapped in list
                    return [embeddings] if isinstance(embeddings, list) else [[embeddings]]
            else:
                raise ValueError(f"Unexpected embedding response format: {results}")
        except Exception as e:
            logger.error(f"Error generating batch embeddings: {e}")
            raise RuntimeError(f"Failed to generate batch embeddings: {e}")
    
    def upsert_vulnerabilities(
        self,
        vectors: List[Dict[str, Any]],
        namespace: Optional[str] = None
    ) -> None:
        """
        Upsert vulnerability vectors into vulns_namespace.
        """
        namespace = namespace or self.vulns_namespace
        try:
            self.index.upsert(vectors=vectors, namespace=namespace)
            logger.info(f"Upserted {len(vectors)} vectors into {namespace}")
        except Exception as e:
            logger.error(f"Error upserting to {namespace}: {e}")
            raise
    
    def upsert_knowledge_base(
        self,
        vectors: List[Dict[str, Any]],
        namespace: Optional[str] = None
    ) -> None:
        """
        Upsert knowledge base vectors into kb_namespace.
        """
        namespace = namespace or self.kb_namespace
        try:
            self.index.upsert(vectors=vectors, namespace=namespace)
            logger.info(f"Upserted {len(vectors)} vectors into {namespace}")
        except Exception as e:
            logger.error(f"Error upserting to {namespace}: {e}")
            raise
    
    def query_vulnerabilities(
        self,
        query_text: str,
        top_k: int = None,
        filter: Optional[Dict[str, Any]] = None,
        namespace: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Query vulnerabilities from vulns_namespace.
        """
        namespace = namespace or self.vulns_namespace
        top_k = top_k or settings.top_k_retrieval
        
        try:
            # Generate query embedding
            query_embedding = self.generate_embedding(query_text)
            
            # Query Pinecone
            results = self.index.query(
                vector=query_embedding,
                top_k=top_k,
                namespace=namespace,
                filter=filter,
                include_metadata=True
            )
            
            return results.get("matches", [])
        except Exception as e:
            logger.error(f"Error querying {namespace}: {e}")
            raise
    
    def query_knowledge_base(
        self,
        query_text: str,
        top_k: int = None,
        filter: Optional[Dict[str, Any]] = None,
        namespace: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Query knowledge base from kb_namespace.
        """
        namespace = namespace or self.kb_namespace
        top_k = top_k or settings.top_k_retrieval
        
        try:
            # Generate query embedding
            query_embedding = self.generate_embedding(query_text)
            
            # Query Pinecone
            results = self.index.query(
                vector=query_embedding,
                top_k=top_k,
                namespace=namespace,
                filter=filter,
                include_metadata=True
            )
            
            return results.get("matches", [])
        except Exception as e:
            logger.error(f"Error querying {namespace}: {e}")
            raise
    
    def query_both_namespaces(
        self,
        query_text: str,
        top_k: int = None,
        vulns_filter: Optional[Dict[str, Any]] = None,
        kb_filter: Optional[Dict[str, Any]] = None
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Query both namespaces simultaneously.
        
        Args:
            query_text: Query text to search for
            top_k: Number of results per namespace
            vulns_filter: Optional filter for vulnerabilities namespace
            kb_filter: Optional filter for knowledge base namespace
            
        Returns:
            Dictionary with 'vulns' and 'kb' keys containing results
        """
        top_k = top_k or settings.top_k_retrieval
        
        try:
            # Generate query embedding once
            query_embedding = self.generate_embedding(query_text)
            
            # Query both namespaces
            vulns_results = self.index.query(
                vector=query_embedding,
                top_k=top_k,
                namespace=self.vulns_namespace,
                filter=vulns_filter,
                include_metadata=True
            )
            
            kb_results = self.index.query(
                vector=query_embedding,
                top_k=top_k,
                namespace=self.kb_namespace,
                filter=kb_filter,
                include_metadata=True
            )
            
            return {
                "vulns": vulns_results.get("matches", []),
                "kb": kb_results.get("matches", [])
            }
        except Exception as e:
            logger.error(f"Error querying both namespaces: {e}")
            raise

# Singleton instance
_vector_store_service: Optional[VectorStoreService] = None


def get_vector_store_service() -> VectorStoreService:
    """Get or create singleton VectorStoreService instance."""
    global _vector_store_service
    if _vector_store_service is None:
        _vector_store_service = VectorStoreService()
    return _vector_store_service

