from __future__ import annotations

from datetime import datetime
import uuid
from typing import Optional

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class Hosts(Base):
    id: Mapped[str] = mapped_column(primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id: Mapped[Optional[str]] = mapped_column(ForeignKey("clients.id"), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    os: Mapped[Optional[str]] = mapped_column(String(255))
    last_scanned: Mapped[Optional[datetime]] = mapped_column(nullable=True)


