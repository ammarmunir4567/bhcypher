from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional, Union

from app.services.vector_store_service import get_vector_store_service
from app.core.config import settings

logger = logging.getLogger(__name__)


def chunk_text_with_overlap(
    text: str,
    chunk_size: int = None,
    overlap: int = None
) -> List[str]:
    """
    Split text into overlapping chunks for better context preservation.
    
    """
    if chunk_size is None:
        chunk_size = settings.chunk_size
    if overlap is None:
        overlap = settings.chunk_overlap
    
    if len(text) <= chunk_size:
        return [text]
    
    chunks = []
    start = 0
    
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        
        if end < len(text):
            last_period = chunk.rfind('.', max(0, len(chunk) - 100))
            last_newline = chunk.rfind('\n', max(0, len(chunk) - 100))
            break_point = max(last_period, last_newline)
            
            # Only break if we're past halfway through the chunk
            if break_point > len(chunk) * 0.5:
                chunk = chunk[:break_point + 1]
                end = start + break_point + 1
        
        chunks.append(chunk.strip())
        
        # Move start position with overlap
        start = end - overlap
        if start >= len(text):
            break
    
    return chunks


def build_kb_entry(
    text: Union[str, list, dict],
    topic: str,
    category: str,
    source: str = "AI Response",
    cve_id: Optional[str] = None,
    scan_file_id: Optional[str] = None,
    scan_s3_path: Optional[str] = None,
    report_html_s3: Optional[str] = None,
    report_pdf_s3: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Build KB entry structure(s) for storing in kb_namespace.
    If text exceeds chunk_size, returns multiple entries (chunks) with overlap.
    Accepts text as string, list, or dict - non-strings will be converted to JSON.
    
    """
    # Handle various input types (str, list, dict)
    if isinstance(text, list):
        # If it's a list, convert to JSON string for storage
        text = json.dumps(text, indent=2)
    elif isinstance(text, dict):
        # If it's a dict, convert to JSON string for storage
        text = json.dumps(text, indent=2)
    elif not isinstance(text, str):
        # Convert any other type to string
        text = str(text)
    
    text = text.strip()
    if not text:
        return []
    
    # Extract first line as summary
    summary = text.split("\n")[0][:200] if text else ""
    
    # Check if chunking is needed
    if len(text) > settings.chunk_size:
        # Chunk the text
        text_chunks = chunk_text_with_overlap(
            text,
            chunk_size=settings.chunk_size,
            overlap=settings.chunk_overlap
        )
        total_chunks = len(text_chunks)
        
        # Generate base topic slug for consistent chunk IDs
        topic_slug = topic.lower().replace(" ", "-").replace("_", "-")
        base_id = f"kb-{topic_slug}-{uuid.uuid4().hex[:8]}"
        
        # Create one entry per chunk
        kb_entries = []
        for chunk_idx, chunk_text in enumerate(text_chunks):
            chunk_id = f"{base_id}-chunk-{chunk_idx}"
            
            metadata = {
                "source_type": "kb_article",
                "topic": topic,
                "category": category,
                "source": source,
                "created_at": datetime.utcnow().isoformat(),
                "summary": summary,  
                "text": chunk_text,  
                "chunk_index": chunk_idx,
                "total_chunks": total_chunks,
            }
            
            # Add optional fields
            if cve_id:
                metadata["cve_id"] = cve_id
            
            if scan_file_id:
                metadata["scan_file_id"] = scan_file_id
            
            # Add S3 paths
            if scan_s3_path:
                metadata["scan_s3_path"] = scan_s3_path
            
            if report_html_s3:
                metadata["report_html_s3"] = report_html_s3
            
            if report_pdf_s3:
                metadata["report_pdf_s3"] = report_pdf_s3
            
            kb_entries.append({
                "id": chunk_id,
                "text": chunk_text,  # Embed this chunk
                "metadata": metadata
            })
        
        logger.info(f"Chunked KB entry '{topic}' into {total_chunks} chunks")
        return kb_entries
    else:
        # Single entry, no chunking needed
        topic_slug = topic.lower().replace(" ", "-").replace("_", "-")
        kb_id = f"kb-{topic_slug}-{uuid.uuid4().hex[:8]}"
        
        metadata = {
            "source_type": "kb_article",
            "topic": topic,
            "category": category,
            "source": source,
            "created_at": datetime.utcnow().isoformat(),
            "summary": summary,
            "text": text,
        }
        
        # Add optional fields
        if cve_id:
            metadata["cve_id"] = cve_id
        
        if scan_file_id:
            metadata["scan_file_id"] = scan_file_id
        
        # Add S3 paths
        if scan_s3_path:
            metadata["scan_s3_path"] = scan_s3_path
        
        if report_html_s3:
            metadata["report_html_s3"] = report_html_s3
        
        if report_pdf_s3:
            metadata["report_pdf_s3"] = report_pdf_s3
        
        return [{
            "id": kb_id,
            "text": text,
            "metadata": metadata
        }]


def extract_kb_entries_from_ai_report(
    ai_report: Dict,
    scan_file_id: Optional[str] = None,
    scan_s3_path: Optional[str] = None,
    report_html_s3: Optional[str] = None,
    report_pdf_s3: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Extract KB entries from AI-generated report.
    """
    kb_entries = []
    
    # Extract recommendations from individual findings
    findings = ai_report.get("findings", [])
    for finding in findings:
        cve_id = finding.get("cve_id")
        recommendation = finding.get("recommendation", "")
        impact = finding.get("impact", "")
        title = finding.get("title", "")
        
        if recommendation:
            kb_text = f"{title or cve_id or 'Vulnerability'} Remediation:\n\n"
            if impact:
                kb_text += f"Impact: {impact}\n\n"
            kb_text += f"Recommendation: {recommendation}"
            
            # Determine topic from CVE or title
            topic = cve_id or title or "Vulnerability Remediation"
            
            kb_entry_list = build_kb_entry(
                text=kb_text,
                topic=topic,
                category="mitigation",
                source="AI Response",
                cve_id=cve_id,
                scan_file_id=scan_file_id,
                scan_s3_path=scan_s3_path,
                report_html_s3=report_html_s3,
                report_pdf_s3=report_pdf_s3
            )
            kb_entries.extend(kb_entry_list)  
    
    # Extract overall recommendations
    overall_recommendations = ai_report.get("recommendations", "")
    if overall_recommendations:
        kb_entry_list = build_kb_entry(
            text=overall_recommendations,
            topic="Overall Security Recommendations",
            category="best_practices",
            source="AI Response",
            scan_file_id=scan_file_id,
            scan_s3_path=scan_s3_path,
            report_html_s3=report_html_s3,
            report_pdf_s3=report_pdf_s3
        )
        kb_entries.extend(kb_entry_list) 
    
    # Extract executive summary 
    executive_summary = ai_report.get("executive_summary", "")
    if executive_summary:
        kb_entry_list = build_kb_entry(
            text=executive_summary,
            topic="Security Assessment Summary",
            category="assessment",
            source="AI Response",
            scan_file_id=scan_file_id,
            scan_s3_path=scan_s3_path,
            report_html_s3=report_html_s3,
            report_pdf_s3=report_pdf_s3
        )
        kb_entries.extend(kb_entry_list) 
    
    return kb_entries


def embed_and_store_kb_entries(
    kb_entries: List[Dict[str, Any]]
) -> List[str]:
    """
    Embed and store KB entries in kb_namespace.
    """
    if not kb_entries:
        logger.warning("No KB entries to store")
        return []
    
    vector_store = get_vector_store_service()
    
    # Generate embeddings in batch
    embedding_texts = [entry["text"] for entry in kb_entries]
    logger.info(f"Generating embeddings for {len(embedding_texts)} KB entries...")
    
    try:
        embeddings = vector_store.generate_embeddings_batch(embedding_texts)
    except Exception as e:
        logger.error(f"Error generating embeddings: {e}")
        raise
    
    # Prepare vectors for Pinecone
    vectors = []
    for i, kb_entry in enumerate(kb_entries):
        vectors.append({
            "id": kb_entry["id"],
            "values": embeddings[i],
            "metadata": kb_entry["metadata"]
        })
    
    # Upsert to Pinecone kb_namespace
    logger.info(f"Upserting {len(vectors)} KB entries to kb_namespace...")
    vector_store.upsert_knowledge_base(vectors)
    
    logger.info(f"Successfully stored {len(vectors)} KB entries in Pinecone")
    return [v["id"] for v in vectors]


def store_ai_report_in_kb(
    ai_report: Dict,
    scan_file_id: Optional[str] = None,
    scan_s3_path: Optional[str] = None,
    report_html_s3: Optional[str] = None,
    report_pdf_s3: Optional[str] = None
) -> List[str]:
    """
    Extract KB entries from AI report and store in kb_namespace.
    """
    # Extract KB entries from AI report
    kb_entries = extract_kb_entries_from_ai_report(
        ai_report=ai_report,
        scan_file_id=scan_file_id,
        scan_s3_path=scan_s3_path,
        report_html_s3=report_html_s3,
        report_pdf_s3=report_pdf_s3
    )
    
    if not kb_entries:
        logger.warning("No KB entries extracted from AI report")
        return []
    
    # Embed and store
    stored_ids = embed_and_store_kb_entries(kb_entries)
    
    return stored_ids

