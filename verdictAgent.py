
from models import ParsedLog,SOCVerdict
from threatdetectionAgent import ThreatIntel
from behaviourCorrelationAgent import BehaviorResult



def soc_decision(
    parsed: ParsedLog,
    intel: ThreatIntel,
    behavior: BehaviorResult
) -> SOCVerdict:

    if intel.reputation == "malicious" and behavior.brute_force_detected:
        return SOCVerdict(
            alert_name="SSH Brute Force Attack Detected",
            severity="High",
            confidence=0.94,
            mitre_technique="T1110 - Brute Force",
            recommendations=[
                "Block source IP",
                "Audit SSH logs for successful access",
                "Enable fail2ban",
                "Rotate credentials"
            ]
        )

    return SOCVerdict(
        alert_name="Suspicious Authentication Activity",
        severity="Medium",
        confidence=0.6,
        mitre_technique="T1078 - Valid Accounts",
        recommendations=["Monitor activity", "Increase logging"]
    )
