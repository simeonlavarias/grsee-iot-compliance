from flask import Flask, render_template, redirect, url_for
import json
from pathlib import Path

from rule_engine import evaluate_events, evaluate_event

app = Flask(__name__)

DATA_PATH = Path(__file__).parent / "data" / "mock_events.json"


def load_events():
    if not DATA_PATH.exists():
        return []
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def compute_dashboard_stats(events):
    total = len(events)

    # Counts by severity
    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for e in events:
        sev = (e.get("severity") or "").strip().lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Counts by event type
    event_type_counts = {}
    for e in events:
        t = e.get("event_type", "UNKNOWN")
        event_type_counts[t] = event_type_counts.get(t, 0) + 1

    # Counts by zone
    zone_counts = {}
    for e in events:
        z = e.get("zone", "UNKNOWN")
        zone_counts[z] = zone_counts.get(z, 0) + 1

    # Recent alerts = latest HIGH/CRITICAL events (top 5)
    high_alerts = [e for e in events if (e.get("severity", "").lower() in ["high", "critical"])]
    high_alerts = sorted(high_alerts, key=lambda e: e.get("timestamp", ""), reverse=True)[:5]

    # -----------------------------
    # Compliance KPIs (Rule Engine)
    # -----------------------------
    violations_count = 0
    compliant_count = 0

    for e in events:
        result = evaluate_event(e)
        if result["policy_result"]["is_violation"]:
            violations_count += 1
        else:
            compliant_count += 1

    compliance_percent = round((compliant_count / total) * 100, 1) if total > 0 else 0.0
    violation_percent = round((violations_count / total) * 100, 1) if total > 0 else 0.0

    return {
        "total": total,
        "severity_counts": severity_counts,
        "event_type_counts": event_type_counts,
        "zone_counts": zone_counts,
        "recent_alerts": high_alerts,

        # New KPIs
        "violations_count": violations_count,
        "compliant_count": compliant_count,
        "compliance_percent": compliance_percent,
        "violation_percent": violation_percent
    }



@app.route("/")
def home():
    return redirect(url_for("dashboard"))


@app.route("/events")
def events():
    events_list = load_events()
    events_list = sorted(events_list, key=lambda e: e.get("timestamp", ""), reverse=True)

    # Evaluate compliance status for each event
    enriched_events = []
    for e in events_list:
        result = evaluate_event(e)
        status = "VIOLATION" if result["policy_result"]["is_violation"] else "COMPLIANT"
        enriched_events.append({
            **e,
            "compliance_status": status
        })

    return render_template("events.html", events=enriched_events)


@app.route("/dashboard")
def dashboard():
    events_list = load_events()
    events_list = sorted(events_list, key=lambda e: e.get("timestamp", ""), reverse=True)

    stats = compute_dashboard_stats(events_list)

    # Top 5 event types
    top_event_types = sorted(
        stats["event_type_counts"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    # Top 5 zones by event volume
    top_zones = sorted(
        stats["zone_counts"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    # -----------------------------
    # Compliance by Zone (NEW)
    # -----------------------------
    zone_breakdown = {}

    for e in events_list:
        zone = e.get("zone", "UNKNOWN")
        zone_breakdown.setdefault(zone, {"total": 0, "violations": 0})

        zone_breakdown[zone]["total"] += 1

        result = evaluate_event(e)
        if result["policy_result"]["is_violation"]:
            zone_breakdown[zone]["violations"] += 1

    zone_rows = []
    for zone, counts in zone_breakdown.items():
        total = counts["total"]
        violations = counts["violations"]
        compliant = total - violations
        compliance_percent = round((compliant / total) * 100, 1) if total > 0 else 0.0

        zone_rows.append({
            "zone": zone,
            "total": total,
            "violations": violations,
            "compliance_percent": compliance_percent
        })

    # Sort worst (lowest compliance) first
    zone_rows = sorted(zone_rows, key=lambda r: r["compliance_percent"])

    threshold = 90.0

    return render_template(
        "dashboard.html",
        stats=stats,
        top_event_types=top_event_types,
        top_zones=top_zones,
        zone_rows=zone_rows,
        threshold=threshold
    )


@app.route("/violations")
def violations():
    events_list = load_events()
    events_list = sorted(events_list, key=lambda e: e.get("timestamp", ""), reverse=True)

    processed = evaluate_events(events_list)

    # Join raw + processed by index (same order)
    merged = []
    for raw, proc in zip(events_list, processed):
        merged.append({"raw": raw, "proc": proc})

    # Only violations
    violations_only = [m for m in merged if m["proc"]["policy_result"]["is_violation"]]

    return render_template("violations.html", violations=violations_only)

@app.route("/event/<event_id>")
def event_detail(event_id):
    events_list = load_events()
    # Find the event by id
    target = next((e for e in events_list if e.get("event_id") == event_id), None)

    if target is None:
        return render_template("event_detail.html", found=False, event_id=event_id)

    processed = evaluate_event(target)
    return render_template("event_detail.html", found=True, raw=target, proc=processed)

if __name__ == "__main__":
    app.run(debug=True)
