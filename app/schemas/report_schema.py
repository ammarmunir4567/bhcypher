from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel


class ReportType(str, Enum):
    INDIVIDUAL = "INDIVIDUAL"
    SMB = "SMB"
    MSP = "MSP"
    ENTERPRISE = "ENTERPRISE"


class Report(BaseModel):
    id: str
    client_id: str
    report_type: ReportType
    s3_path_html: str
    s3_path_pdf: str
    risk_score: Optional[float] = None
    sha256_hash: str


