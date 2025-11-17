from __future__ import annotations

from enum import Enum
import uuid
from typing import Literal

from sqlalchemy import Enum as PgEnum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class NodeType(str, Enum):
    HOST = "HOST"
    VULNERABILITY = "VULNERABILITY"
    CVE = "CVE"
    MITRE_TACTIC = "MITRE_TACTIC"


class EdgeType(str, Enum):
    HAS_VULN = "HAS_VULN"
    LINKED_TO = "LINKED_TO"
    EXPLOITED_BY = "EXPLOITED_BY"


class ThreatGraphEdges(Base):
    id: Mapped[str] = mapped_column(primary_key=True, default=lambda: str(uuid.uuid4()))
    source_id: Mapped[str] = mapped_column(String, nullable=False)
    source_type: Mapped[NodeType] = mapped_column(PgEnum(NodeType, name="tg_node_type"), nullable=False)
    target_id: Mapped[str] = mapped_column(String, nullable=False)
    target_type: Mapped[NodeType] = mapped_column(PgEnum(NodeType, name="tg_node_type"), nullable=False)
    relationship: Mapped[EdgeType] = mapped_column(PgEnum(EdgeType, name="tg_edge_type"), nullable=False)


