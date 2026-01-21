from datetime import datetime

# -----------------------------
# Business context configuration
# -----------------------------

BUSINESS_HOURS_START = 8   # 08:00
BUSINESS_HOURS_END = 18    # 18:00

RFID_DENIED_THRESHOLD = 3
SERVER_TEMP_THRESHOLD = 30.0  # Celsius


# -----------------------------
# Helper functions
# -----------------------------

def parse_hour(timestamp_str):
    """
    Extract hour from ISO-like timestamp string.
    Expected format: YYYY-MM-DD HH:MM:SS
    """
    try:
        return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S").hour
    except Exception:
        return None


# -----------------------------
# Core rule evaluation
# -----------------------------

def evaluate_event(event):
    """
    Evaluates a single event against predefined compliance rules.
    Returns a structured decision used by dashboard, reports, incidents.
    """

    # Default outcome (COMPLIANT)
    result = {
        "policy_result": {
            "is_violation": False,
            "policy_name": "NO_VIOLATION",
            "reason": "Event is within defined policy conditions."
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

    event_type = event.get("event_type")
    zone = event.get("zone")
    severity = event.get("severity", "").lower()
    timestamp = event.get("timestamp", "")

    # ==========================================================
    # RULE 1: RFID access AFTER BUSINESS HOURS
    # ==========================================================
    if event_type == "RFID_ACCESS_GRANTED":
        hour = parse_hour(timestamp)
        if hour is not None and (hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END):
            result["policy_result"] = {
                "is_violation": True,
                "policy_name": "AFTER_HOURS_PHYSICAL_ACCESS",
                "reason": "RFID access occurred outside approved business hours."
            }

            result["compliance_mapping"]["iso27001_controls"].append({
                "control_id": "A.11.1.2",
                "title": "Physical entry controls"
            })

            result["incident"] = {
                "create_incident": True,
                "incident_type": "UNAUTHORISED_PHYSICAL_ACCESS"
            }

    # ==========================================================
    # RULE 2: MULTIPLE RFID ACCESS DENIED ATTEMPTS
    # ==========================================================
    if event_type == "RFID_ACCESS_DENIED":
        denied_count = event.get("denied_attempts", 1)

        if denied_count >= RFID_DENIED_THRESHOLD:
            result["policy_result"] = {
                "is_violation": True,
                "policy_name": "SUSPICIOUS_ACCESS_ATTEMPTS",
                "reason": f"{denied_count} consecutive RFID access denial attempts detected."
            }

            result["compliance_mapping"]["iso27001_controls"].append({
                "control_id": "A.11.1.3",
                "title": "Securing offices, rooms and facilities"
            })

            result["incident"] = {
                "create_incident": True,
                "incident_type": "POTENTIAL_INTRUSION_ATTEMPT"
            }

    # ==========================================================
    # RULE 3: SERVER ROOM TEMPERATURE EXCEEDED
    # ==========================================================
    if event_type == "TEMP_THRESHOLD_EXCEEDED" and zone == "SERVER_ROOM":
        temp = event.get("temperature")

        if temp is not None and temp > SERVER_TEMP_THRESHOLD:
            result["policy_result"] = {
                "is_violation": True,
                "policy_name": "ENVIRONMENTAL_CONTROL_FAILURE",
                "reason": f"Server room temperature exceeded safe threshold ({temp}°C)."
            }

            result["compliance_mapping"]["iso27001_controls"].append({
                "control_id": "A.11.2.2",
                "title": "Supporting utilities"
            })

            result["incident"] = {
                "create_incident": True,
                "incident_type": "ENVIRONMENTAL_RISK"
            }

    # ==========================================================
    # RULE 4: CAMERA TAMPERING IN CASH / PAYMENT AREA
    # ==========================================================
    if event_type == "CAMERA_TAMPER_DETECTED" and zone == "CASH_VAULT":
        result["policy_result"] = {
            "is_violation": True,
            "policy_name": "SURVEILLANCE_TAMPERING",
            "reason": "Camera tampering detected in payment-sensitive area."
        }

        result["compliance_mapping"]["pcidss_requirements"].append({
            "requirement_id": "PCI DSS Req. 9",
            "title": "Restrict physical access to cardholder data"
        })

        result["incident"] = {
            "create_incident": True,
            "incident_type": "SURVEILLANCE_COMPROMISE"
        }

    return result
