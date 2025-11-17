from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class Host(BaseModel):
    id: str
    client_id: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os: Optional[str] = None
    last_scanned: Optional[datetime] = None


