from models import ThreatIntel

def threat_intel_lookup(src_ip: str) -> ThreatIntel:
  if src_ip.startswith("185."):
        return ThreatIntel(
            reputation="malicious",
            confidence=0.92,
            known_activity=["SSH brute-force", "Botnet traffic"]
        )
  return ThreatIntel(
        reputation="unknown",
        confidence=0.2,
        known_activity=[]
  )
   