from __future__ import annotations

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from app.services.s3_service import download_json, upload_report
from app.services.report_service import generate_report_from_scan
from app.services.msp_report_service import generate_msp_report_from_scan
from app.services.vuln_embedding_service import embed_and_store_vulnerabilities, extract_severity_from_ai_report
from app.services.kb_service import store_ai_report_in_kb
from app.utils.json_validator import validate_scan_json
from app.api.dependencies import get_db
from app.services.persistence_service import find_or_create_host, create_scan_file, create_report


router = APIRouter(prefix="/ingest", tags=["ingestion"])


@router.post("/msp-s3-callback")
def msp_s3_callback(s3_path: str, db: Session = Depends(get_db)):
    """
    MSP report ingestion endpoint triggered when a new MSP scan file arrives in S3.
    
    This endpoint:
    1. Downloads MSP scan file from S3
    2. Validates the JSON structure
    3. Generates MSP Cyber Hygiene & Credential Exposure report using LangGraph agents
    4. Uploads HTML/PDF reports to S3
    5. Stores report metadata in database
    
    Expected S3 file format:
    {
        "browsers": [{"url": "...", "username": "...", "password": "...", "browser": "Chrome", ...}],
        "os": [{"service": "WiFi Network", "account": "...", "password": "...", ...}],
        "apps": [{"application": "Discord", "username": "...", "password": "...", ...}],
        "statsData": {"browser_count": 3, "os_count": 2, "app_count": 2, ...},
        "systemData": {
            "user_accounts": [...],
            "running_services": [...],
            "installed_software": [...],
            "open_ports": [...]
        },
        "systemStats": {
            "system": {
                "hostname": "DESKTOP-5UU61JF",
                "os_name": "Windows",
                "os_version": "10 (19045) 19045"
            }
        },
        "vulnerabilities": {...}
    }
    """
    try:
        # Download MSP scan file from S3
        msp_scan = download_json(s3_path)
        
        # Basic validation - check for required keys from credential scanner
        required_keys = ["browsers", "os", "apps", "systemData", "systemStats"]
        missing_keys = [key for key in required_keys if key not in msp_scan]
        
        if missing_keys:
            # Invalid format detected
            current_keys = list(msp_scan.keys())
            raise HTTPException(
                status_code=400, 
                detail={
                    "error": "MSP scan validation failed",
                    "missing_keys": missing_keys,
                    "found_keys": current_keys,
                    "expected_format": "Credential scanner output with: browsers, os, apps, systemData, systemStats",
                    "hint": "This appears to be a different scan format. Use /ingest/s3-callback for vulnerability scans."
                }
            )
        
        # Extract endpoint information from systemStats.system (same structure as pentest scans)
        sys = msp_scan.get("systemStats", {}).get("system", {})
        hostname = sys.get("hostname", "unknown-host")
        os_name = sys.get("os_name", "Unknown")
        os_version = sys.get("os_version", "Unknown")
        
        # Persist Host and Scan file
        host = find_or_create_host(db, hostname, os_name, os_version)
        scan_row = create_scan_file(db, s3_path=s3_path, raw_json=msp_scan, host_id=host.id)
        
        # Generate MSP report using LangGraph multi-agent system
        html_str, pdf_bytes, summary, report_data = generate_msp_report_from_scan(msp_scan)
        
        # Upload reports to S3
        html_s3, pdf_s3 = upload_report(
            html_str.encode("utf-8"),
            pdf_bytes,
            hostname=hostname,
            encrypt=False,
            public=True,
        )
        
        # Save report record with MSP report type
        from app.models import ReportType
        create_report(
            db,
            host_id=host.id,
            scan_file_id=scan_row.id,
            html_inline=html_str,
            s3_html=html_s3,
            s3_pdf=pdf_s3,
            summary=summary,
            risk_score=summary.get("risk_score"),
            report_type=ReportType.MSP,
        )
        
        db.commit()
        
        return {
            "status": "success",
            "endpoint": hostname,
            "html_s3": html_s3,
            "pdf_s3": pdf_s3,
            "summary": summary,
        }
        
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        import traceback
        error_detail = f"MSP report generation failed: {str(e)}"
        print(f"ERROR in MSP ingestion: {error_detail}")
        traceback.print_exc()
        db.rollback()
        raise HTTPException(status_code=500, detail=error_detail)


@router.post("/pentest-s3-callback")
def pentest_s3_callback(s3_path: str, db: Session = Depends(get_db)):
    """
    Comprehensive Pentest Report ingestion endpoint.
    
    This endpoint uses LLM-based analysis to:
    1. Interpret limited scan data intelligently
    2. Map CVEs to installed software
    3. Identify outdated/EOL software
    4. Analyze port/service exposure
    5. Detect configuration issues
    6. Generate realistic security findings
    7. Create professional penetration test report
    
    The LLM enriches the scan data to generate findings that would typically require
    multiple specialized security tools (Nessus, OpenVAS, configuration scanners, etc.)
    """
    try:
        # Download scan file from S3
        scan = download_json(s3_path)
        
        # Validate JSON schema
        is_valid, error_msg = validate_scan_json(scan)
        if not is_valid:
            raise HTTPException(status_code=400, detail=f"Schema validation failed: {error_msg}")
        
        # Persist Host and Scan file
        sys = scan.get("systemStats", {}).get("system", {})
        host = find_or_create_host(db, sys.get("hostname"), sys.get("os_name"), sys.get("os_version"))
        scan_row = create_scan_file(db, s3_path=s3_path, raw_json=scan, host_id=host.id)

        # Generate comprehensive pentest report using LLM analysis
        html_str, pdf_bytes, summary, report_data = generate_report_from_scan(scan, report_type="pentest")
        
        # Extract severity mapping from AI report 
        cve_severity_map = extract_severity_from_ai_report(report_data)
        
        # Embed and store vulnerabilities 
        stored_vector_ids = embed_and_store_vulnerabilities(
            scan_json=scan,
            s3_bucket_url=s3_path,
            scan_file_id=scan_row.id,
            cve_severity_map=cve_severity_map
        )
        
        # Upload reports to S3 
        html_s3, pdf_s3 = upload_report(
            html_str.encode("utf-8"),
            pdf_bytes,
            hostname=host.hostname or "unknown-host",
            encrypt=False,
            public=True,
        )
        
        # Store AI-generated summaries and recommendations 
        stored_kb_ids = store_ai_report_in_kb(
            ai_report=report_data,
            scan_file_id=scan_row.id,
            scan_s3_path=s3_path,
            report_html_s3=html_s3,
            report_pdf_s3=pdf_s3
        )

        # Save report record with ENTERPRISE report type (for comprehensive pentest reports)
        from app.models import ReportType
        create_report(
            db,
            host_id=host.id,
            scan_file_id=scan_row.id,
            html_inline=html_str,
            s3_html=html_s3,
            s3_pdf=pdf_s3,
            summary=summary,
            risk_score=summary.get("risk_score"),
            report_type=ReportType.ENTERPRISE,
        )
        
        db.commit()
        
        return {
            "status": "success",
            "report_type": "pentest",
            "html_s3": html_s3,
            "pdf_s3": pdf_s3,
            "summary": summary,
            "enriched_by_llm": True,
        }
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        import traceback
        error_detail = f"Pentest report generation failed: {str(e)}"
        print(f"ERROR in pentest ingestion: {error_detail}")
        traceback.print_exc()
        db.rollback()
        raise HTTPException(status_code=500, detail=error_detail)


