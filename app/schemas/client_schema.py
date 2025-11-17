from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, EmailStr


class ClientType(str, Enum):
    INDIVIDUAL = "INDIVIDUAL"
    SMB = "SMB"
    MSP = "MSP"
    ENTERPRISE = "ENTERPRISE"


class Client(BaseModel):
    id: str
    name: str
    type: ClientType
    contact_email: Optional[EmailStr] = None
    created_at: datetime


