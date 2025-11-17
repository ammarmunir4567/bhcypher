from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional

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
        
            if break_point > len(chunk) * 0.5:
                chunk = chunk[:break_point + 1]
                end = start + break_point + 1
        
        chunks.append(chunk.strip())
        
        # Move start position with overlap
        start = end - overlap
        if start >= len(text):
            break
    
    return chunks


def build_embedding_text(
    hostname: str,
    os_name: str,
    os_version: Optional[str],
    cve_id: str,
    description: str,
    severity: str,
    risk_score: float
) -> str:
    """
    Build formatted text paragraph for embedding from vulnerability data.
    """
    # Build OS string
    os_str = os_name or "Unknown OS"
    if os_version:
        os_str = f"{os_name} {os_version}"
    
    # Build host string
    host_str = f"Host {hostname}" if hostname else "Host"
    
    # Build main paragraph with only the data from scan
    text_parts = [
        f"{host_str} running {os_str} has vulnerability {cve_id}.",
        f"Description: {description or 'No description available'}.",
        f"Severity: {severity.capitalize()}, Risk score {risk_score}."
    ]
    
    return " ".join(text_parts)


def extract_severity_from_ai_report(ai_report: Dict) -> Dict[str, str]:
    """
    Extract CVE ID to severity mapping from AI report findings.
    
    Args:
        ai_report: AI-generated report with findings array
        
    Returns:
        Dictionary mapping CVE ID to severity (lowercase)
    """
    cve_to_severity = {}
    findings = ai_report.get("findings", [])
    
    for finding in findings:
        cve_id = finding.get("cve_id")
        severity = finding.get("severity", "")
        if cve_id and severity:
            cve_to_severity[cve_id] = str(severity).lower()
    
    return cve_to_severity


def _extract_severity_from_vulnerability(vulnerability: Dict, summary: Dict) -> str:
    """
    Extract severity from vulnerability data as it comes.
    Only checks if severity exists in the data, returns empty string if not found.
    """
    # Check if severity is directly in the vulnerability object
    if "severity" in vulnerability:
        return str(vulnerability["severity"]).lower()
    
    # Check if severity is in the CVE object
    cve = vulnerability.get("cve", {})
    if "severity" in cve:
        return str(cve["severity"]).lower()
    
    # If not found, return empty string (will be stored as-is)
    return ""


def normalize_vulnerability_for_embedding(
    scan_json: Dict,
    vulnerability: Dict,
    s3_bucket_url: str,
    scan_file_id: Optional[str] = None,
    cve_severity_map: Optional[Dict[str, str]] = None
) -> List[Dict[str, Any]]:
    """
    Normalize a single vulnerability from scan JSON into embedding format.
    """
    # Extract system info
    sys = scan_json.get("systemStats", {}).get("system", {})
    hostname = sys.get("hostname") or "unknown-host"
    os_name = sys.get("os_name") or "Unknown"
    os_version = sys.get("os_version")
    
    # Extract vulnerability info
    cve = vulnerability.get("cve", {})
    cve_id = cve.get("id") or "UNKNOWN-CVE"
    descriptions = cve.get("descriptions", [])
    description = next(
        (d.get("value") for d in descriptions if d.get("lang") == "en"),
        None
    ) or "No description available"
    
    # Extract summary for risk_score
    summary = scan_json.get("vulnerabilities", {}).get("summary", {})
    risk_score = summary.get("risk_score", 0.0)
    
    # Extract severity - prioritize AI report, then scan data
    severity = ""
    if cve_severity_map and cve_id in cve_severity_map:
        # Use severity from AI report
        severity = cve_severity_map[cve_id]
    else:
        # Fall back to extracting from scan data
        severity = _extract_severity_from_vulnerability(vulnerability, summary)
    
    # Build embedding text
    embedding_text = build_embedding_text(
        hostname=hostname,
        os_name=os_name,
        os_version=os_version,
        cve_id=cve_id,
        description=description,
        severity=severity if severity else "unknown",
        risk_score=risk_score
    )
    
    # Check if chunking is needed
    if len(embedding_text) > settings.chunk_size:
        # Chunk the text
        text_chunks = chunk_text_with_overlap(
            embedding_text,
            chunk_size=settings.chunk_size,
            overlap=settings.chunk_overlap
        )
        total_chunks = len(text_chunks)
        
        # Base vector ID: {hostname}-{CVE-ID}
        base_vector_id = f"{hostname}-{cve_id}"
        
        # Create one entry per chunk
        normalized_entries = []
        for chunk_idx, chunk_text in enumerate(text_chunks):
            chunk_vector_id = f"{base_vector_id}-chunk-{chunk_idx}"
            
            # Build metadata
            metadata = {
                "source_type": "vulnerability",
                "S3_bucket_url": s3_bucket_url,
                "hostname": hostname,
                "os_name": os_name,
                "os_version": os_version or "",
                "cve_id": cve_id,
                "severity": severity if severity else "",
                "risk_score": risk_score,
                "text": chunk_text,  
                "full_text": embedding_text,  
                "summary": description,
                "chunk_index": chunk_idx,
                "total_chunks": total_chunks,
            }
            
            # Add optional fields
            if scan_file_id:
                metadata["scan_file_id"] = scan_file_id
            
            if cve.get("published"):
                metadata["published"] = cve.get("published")
            
            if cve.get("lastModified"):
                metadata["last_modified"] = cve.get("lastModified")
            
            normalized_entries.append({
                "id": chunk_vector_id,
                "text": chunk_text,  # Embed this chunk
                "metadata": metadata
            })
        
        logger.info(f"Chunked vulnerability {cve_id} on {hostname} into {total_chunks} chunks")
        return normalized_entries
    else:
        # Single entry, no chunking needed
        vector_id = f"{hostname}-{cve_id}"
        
        # Build metadata
        metadata = {
            "source_type": "vulnerability",
            "S3_bucket_url": s3_bucket_url,
            "hostname": hostname,
            "os_name": os_name,
            "os_version": os_version or "",
            "cve_id": cve_id,
            "severity": severity if severity else "",
            "risk_score": risk_score,
            "text": embedding_text,
            "summary": description,
        }
        
        # Add optional fields
        if scan_file_id:
            metadata["scan_file_id"] = scan_file_id
        
        if cve.get("published"):
            metadata["published"] = cve.get("published")
        
        if cve.get("lastModified"):
            metadata["last_modified"] = cve.get("lastModified")
        
        return [{
            "id": vector_id,
            "text": embedding_text,
            "metadata": metadata
        }]


def embed_and_store_vulnerabilities(
    scan_json: Dict,
    s3_bucket_url: str,
    scan_file_id: Optional[str] = None,
    cve_severity_map: Optional[Dict[str, str]] = None
) -> List[Dict[str, Any]]:
    """
    Process all vulnerabilities from scan JSON, embed them, and store in Pinecone.
    
    Args:
        scan_json: Full scan JSON
        s3_bucket_url: S3 URL where scan file is stored
        scan_file_id: Optional scan file ID from database
        cve_severity_map: Optional mapping of CVE ID to severity from AI report
        
    Returns:
        List of stored vector IDs
    """
    vector_store = get_vector_store_service()
    vulnerabilities = scan_json.get("vulnerabilities", {}).get("vulnerabilities", [])
    
    if not vulnerabilities:
        logger.warning("No vulnerabilities found in scan JSON")
        return []
    
    # Normalize all vulnerabilities
    normalized_vulns = []
    for vuln in vulnerabilities:
        try:
            normalized_list = normalize_vulnerability_for_embedding(
                scan_json=scan_json,
                vulnerability=vuln,
                s3_bucket_url=s3_bucket_url,
                scan_file_id=scan_file_id,
                cve_severity_map=cve_severity_map
            )
            normalized_vulns.extend(normalized_list)
        except Exception as e:
            logger.error(f"Error normalizing vulnerability: {e}")
            continue
    
    if not normalized_vulns:
        logger.warning("No vulnerabilities could be normalized")
        return []
    
    # Generate embeddings in batch
    embedding_texts = [v["text"] for v in normalized_vulns]
    logger.info(f"Generating embeddings for {len(embedding_texts)} vulnerabilities...")
    
    try:
        embeddings = vector_store.generate_embeddings_batch(embedding_texts)
    except Exception as e:
        logger.error(f"Error generating embeddings: {e}")
        raise
    
    # Prepare vectors for Pinecone
    vectors = []
    for i, normalized in enumerate(normalized_vulns):
        vectors.append({
            "id": normalized["id"],
            "values": embeddings[i],
            "metadata": normalized["metadata"]
        })
    
    # Upsert to Pinecone
    logger.info(f"Upserting {len(vectors)} vectors to vulns_namespace...")
    vector_store.upsert_vulnerabilities(vectors)
    
    logger.info(f"Successfully stored {len(vectors)} vulnerabilities in Pinecone")
    return [v["id"] for v in vectors]

