from __future__ import annotations

from datetime import datetime
from typing import Optional, Dict

from sqlalchemy.orm import Session

from app.models.host import Hosts
from app.models.scan_file import ScanFiles, ValidationStatus
from app.models.report import Reports, ReportType


def find_or_create_host(db: Session, hostname: Optional[str], os_name: Optional[str], os_version: Optional[str]) -> Hosts:
    host: Optional[Hosts] = None
    if hostname:
        host = db.query(Hosts).filter(Hosts.hostname == hostname).first()
    if host is None:
        host = Hosts(hostname=hostname, os=os_name)
        db.add(host)
        db.flush()
    else:
        # Update OS info if changed
        if os_name and host.os != os_name:
            host.os = os_name
        if os_version and (host.last_scanned is None):
            # We do not have os_version field on Host; store in os string suffix
            pass
    host.last_scanned = datetime.utcnow()
    db.flush()
    return host


def create_scan_file(
    db: Session,
    s3_path: str,
    raw_json: Dict,
    host_id: Optional[str] = None,
) -> ScanFiles:
    scan_file = ScanFiles(
        s3_path=s3_path,
        upload_time=datetime.utcnow(),
        validation_status=ValidationStatus.VALID,
        raw_json=raw_json,
        host_id=host_id,
    )
    db.add(scan_file)
    db.flush()
    return scan_file


def create_report(
    db: Session,
    host_id: Optional[str],
    scan_file_id: Optional[str],
    html_inline: str,
    s3_html: str,
    s3_pdf: Optional[str],
    summary: Dict,
    risk_score: Optional[float],
    report_type: Optional[ReportType] = None,
) -> Reports:
    report = Reports(
        host_id=host_id,
        scan_file_id=scan_file_id,
        html_inline=html_inline,
        s3_path_html=s3_html,
        s3_path_pdf=s3_pdf or "",
        summary=summary,
        risk_score=risk_score,
        report_type=report_type or ReportType.INDIVIDUAL,
    )
    db.add(report)
    db.flush()
    return report


