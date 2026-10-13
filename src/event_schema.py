
from dataclasses import dataclass
from typing import Optional


@dataclass
class SecurityEvent:
    event_id: str
    case_id: str
    timestamp: str
    source_type: str
    event_type: str
    host: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    raw_event: Optional[str] = None