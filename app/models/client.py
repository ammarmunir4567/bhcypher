from __future__ import annotations

from datetime import datetime
import uuid
from enum import Enum
from typing import Optional

from sqlalchemy import Enum as PgEnum
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class ClientType(str, Enum):
    INDIVIDUAL = "INDIVIDUAL"
    SMB = "SMB"
    MSP = "MSP"
    ENTERPRISE = "ENTERPRISE"


class Clients(Base):
    id: Mapped[str] = mapped_column(primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[ClientType] = mapped_column(PgEnum(ClientType, name="client_type"), nullable=False)
    contact_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)


