from __future__ import annotations
from .base import Base  

# Import models to register their tables with the metadata
from .client import Clients     
from .host import Hosts  
from .scan_file import ScanFiles  
from .report import Reports  
from .risk_score import RiskScores  
from .threat_graph import ThreatGraphEdges
from .vulnerability import Vulnerabilities 


