from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Vulnerability(BaseModel):
    id: str
    host_id: str
    cve_id: Optional[str] = None
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: Optional[Severity] = None
    detected_at: Optional[datetime] = None
    exploit_available: bool = False
    source_file_id: str


