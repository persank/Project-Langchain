from pydantic import BaseModel
from typing import List

class ParsedLog(BaseModel):
    event_type: str
    user: str
    src_ip: str
    host: str
    auth_method: str

class ThreatIntel(BaseModel):
    reputation: str
    confidence: float
    known_activity: List[str]

class BehaviorResult(BaseModel):
    attempt_count: int
    time_window_minutes: int
    brute_force_detected: bool

class SOCVerdict(BaseModel):
    alert_name: str
    severity: str
    confidence: float
    mitre_technique: str
