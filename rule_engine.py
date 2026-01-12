from datetime import datetime, time


def _parse_timestamp(ts: str):
    """
    Parses timestamps like:
    - "2026-01-09T10:15:00"
    - "2026-01-09T10:15:00+08:00" (timezone part ignored for now)
    Returns datetime or None.
    """
    if not ts:
        return None
    # Remove timezone if present (simple approach for MVP)
    ts = ts.split("+")[0].split("Z")[0]
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _is_after_hours(dt: datetime, start_hour=8, end_hour=18):
    """
    Business hours default: 08:00–18:00.
    After-hours is before start_hour or after end_hour.
    """
    if dt is None:
        return False
    start = time(start_hour, 0, 0)
    end = time(end_hour, 0, 0)
    return dt.time() < start or dt.time() > end


def evaluate_event(event: dict) -> dict:
    """
    Takes a raw event dict and returns a processed result containing:
    - policy_result (is_violation, reason)
    - compliance_mapping (ISO/PCI placeholder controls)
    - incident suggestion
    """
    event_type = (event.get("event_type") or "UNKNOWN").strip()
    zone = (event.get("zone") or "UNKNOWN").strip()
    severity = (event.get("severity") or "LOW").strip().upper()
    ts = _parse_timestamp(event.get("timestamp", ""))

    # Default result
    result = {
        "event_id": event.get("event_id"),
        "policy_result": {
            "policy_id": None,
            "policy_name": None,
            "is_violation": False,
            "reason": "No policy violation detected"
        },
        "compliance_mapping": {
            "iso27001_controls": [],
            "pcidss_requirements": []
        },
        "incident": {
            "create_incident": False,
            "incident_type": None
        }
    }

    # -----------------------------
    # RULES (simple v1 ruleset)
    # -----------------------------

    # Rule 1: Denied RFID access is a violation (especially in restricted zones)
    if event_type == "RFID_ACCESS_DENIED":
        result["policy_result"] = {
            "policy_id": "POL-PA-001",
            "policy_name": "Unauthorized physical access attempt",
            "is_violation": True,
            "reason": "RFID access was denied (possible unauthorized attempt)"
        }
        result["compliance_mapping"]["iso27001_controls"] = [
            {"control_id": "A.11.1.2", "title": "Physical entry controls"}
        ]
        result["compliance_mapping"]["pcidss_requirements"] = [
            {"requirement_id": "Req. 9", "title": "Restrict physical access to cardholder data"}
        ]
        result["incident"] = {
            "create_incident": True,
            "incident_type": "UNAUTHORIZED_ACCESS_ATTEMPT"
        }
        return result

    # Rule 2: Motion detected after-hours in sensitive zones
    if event_type == "MOTION_DETECTED" and _is_after_hours(ts) and zone in {"CASH_VAULT", "SERVER_ROOM"}:
        result["policy_result"] = {
            "policy_id": "POL-PA-002",
            "policy_name": "After-hours motion in restricted zone",
            "is_violation": True,
            "reason": f"Motion detected after-hours in restricted zone ({zone})"
        }
        result["compliance_mapping"]["iso27001_controls"] = [
            {"control_id": "A.11.1.1", "title": "Physical security perimeter"}
        ]
        result["compliance_mapping"]["pcidss_requirements"] = [
            {"requirement_id": "Req. 9", "title": "Restrict physical access to cardholder data"}
        ]
        result["incident"] = {
            "create_incident": True,
            "incident_type": "SUSPICIOUS_AFTER_HOURS_ACTIVITY"
        }
        return result

    # Rule 3: Temperature exceeded in server room = environmental violation
    if event_type == "TEMP_THRESHOLD_EXCEEDED" and zone == "SERVER_ROOM":
        result["policy_result"] = {
            "policy_id": "POL-ENV-001",
            "policy_name": "Environmental threshold breach",
            "is_violation": True,
            "reason": "Temperature exceeded threshold in server room"
        }
        result["compliance_mapping"]["iso27001_controls"] = [
            {"control_id": "A.11.2.2", "title": "Supporting utilities"}
        ]
        result["compliance_mapping"]["pcidss_requirements"] = [
            {"requirement_id": "Req. 9", "title": "Protect systems from environmental threats"}
        ]
        result["incident"] = {
            "create_incident": True,
            "incident_type": "ENVIRONMENTAL_RISK"
        }
        return result

    # Rule 4: Camera tamper detected = violation
    if event_type == "CAMERA_TAMPER_DETECTED":
        result["policy_result"] = {
            "policy_id": "POL-CCTV-001",
            "policy_name": "CCTV tamper detection",
            "is_violation": True,
            "reason": "Camera tamper detected (possible attempt to disable surveillance)"
        }
        result["compliance_mapping"]["iso27001_controls"] = [
            {"control_id": "A.11.1.4", "title": "Protecting against external and environmental threats"}
        ]
        result["compliance_mapping"]["pcidss_requirements"] = [
            {"requirement_id": "Req. 9", "title": "Use video cameras and protect them from tampering"}
        ]
        result["incident"] = {
            "create_incident": True,
            "incident_type": "SURVEILLANCE_TAMPER"
        }
        return result

    # Otherwise: no violation
    return result


def evaluate_events(events: list[dict]) -> list[dict]:
    """
    Returns processed results for all events.
    """
    return [evaluate_event(e) for e in events]
