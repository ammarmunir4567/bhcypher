from __future__ import annotations

from enum import Enum
from typing import Optional
import uuid

from sqlalchemy import Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class ReportType(str, Enum):
    INDIVIDUAL = "INDIVIDUAL"
    SMB = "SMB"
    MSP = "MSP"
    ENTERPRISE = "ENTERPRISE"
    QUALITATIVE = "QUALITATIVE"


class Reports(Base):
    id: Mapped[str] = mapped_column(primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id: Mapped[Optional[str]] = mapped_column(ForeignKey("clients.id"), nullable=True)
    report_type: Mapped[ReportType] = mapped_column(String(32), nullable=True)
    s3_path_html: Mapped[str] = mapped_column(String, nullable=False)
    s3_path_pdf: Mapped[str] = mapped_column(String, nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float)
    host_id: Mapped[Optional[str]] = mapped_column(ForeignKey("hosts.id"), nullable=True)
    scan_file_id: Mapped[Optional[str]] = mapped_column(ForeignKey("scanfiles.id"), nullable=True)
    html_inline: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    summary: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)


