from models import BehaviorResult


def behavior_analysis(src_ip: str) -> BehaviorResult:
    # Example logic — replace with real Splunk SPL API
    attempts = 27
    return BehaviorResult(
        attempt_count=attempts,
        time_window_minutes=5,
        brute_force_detected=attempts > 10
    )
