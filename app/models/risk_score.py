from __future__ import annotations

from datetime import datetime
import uuid
from typing import Optional

from sqlalchemy import Float, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class RiskScores(Base):
    id: Mapped[str] = mapped_column(primary_key=True, default=lambda: str(uuid.uuid4()))
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), nullable=False)
    overall_risk: Mapped[float] = mapped_column(Float, nullable=False)
    likelihood: Mapped[float] = mapped_column(Float, nullable=False)
    impact: Mapped[float] = mapped_column(Float, nullable=False)
    exploitability: Mapped[float] = mapped_column(Float, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(nullable=False)


