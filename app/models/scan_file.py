from __future__ import annotations

from enum import Enum
from datetime import datetime
import uuid
from typing import Optional

from sqlalchemy import Enum as PgEnum, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class ValidationStatus(str, Enum):
    PENDING = "PENDING"
    VALID = "VALID"
    INVALID = "INVALID"


class ScanFiles(Base):
    id: Mapped[str] = mapped_column(primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id: Mapped[Optional[str]] = mapped_column(ForeignKey("clients.id"), nullable=True)
    s3_path: Mapped[str] = mapped_column(String, nullable=False)
    upload_time: Mapped[datetime] = mapped_column(nullable=False)
    validation_status: Mapped[ValidationStatus] = mapped_column(PgEnum(ValidationStatus, name="validation_status"), nullable=False, default=ValidationStatus.PENDING)
    raw_json: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    host_id: Mapped[Optional[str]] = mapped_column(ForeignKey("hosts.id"), nullable=True)


