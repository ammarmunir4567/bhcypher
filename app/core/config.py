from __future__ import annotations

import os
from dotenv import load_dotenv
from pydantic_settings import BaseSettings

load_dotenv()


class Settings(BaseSettings):
    database_url: str = os.getenv("DATABASE_URL", "postgresql+psycopg://postgres:postgres@localhost:5432/bhcypher")
    pinecone_index: str = os.getenv("PINECONE_INDEX", "threat-kb")
    pinecone_api_key: str = os.getenv("PINECONE_API_KEY", "pcsk_75KbQg_MBmdvPSW2VbvMwm2v1TKT7WaBxq9bxGMtiHVP6TH5xv2NTSUpZL6rhdQ3VoKq6N")
    pinecone_environment: str = os.getenv("PINECONE_ENVIRONMENT", "us-east-1")
    embedding_model: str = os.getenv("EMBEDDING_MODEL", "models/embedding-001")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    
    # RAG Configuration
    vulns_namespace: str = os.getenv("VULNS_NAMESPACE", "vulns_namespace")
    kb_namespace: str = os.getenv("KB_NAMESPACE", "kb_namespace")
    vector_dimension: int = int(os.getenv("VECTOR_DIMENSION", "768"))  # Gemini embedding-001 is 768
    chunk_size: int = int(os.getenv("CHUNK_SIZE", "500"))
    chunk_overlap: int = int(os.getenv("CHUNK_OVERLAP", "50"))
    top_k_retrieval: int = int(os.getenv("TOP_K_RETRIEVAL", "5"))
    
    # if aws is configured enable these,
    s3_bucket: str = os.getenv("S3_BUCKET", "")
    # aws_region: str = os.getenv("AWS_REGION", "us-east-1")
    # kms_key_id: str = os.getenv("KMS_KEY_ID", "")


settings = Settings()
