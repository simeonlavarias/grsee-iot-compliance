from flask import Flask, render_template, redirect, url_for
import json
from pathlib import Path

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

    return {
        "total": total,
        "severity_counts": severity_counts,
        "event_type_counts": event_type_counts,
        "zone_counts": zone_counts,
        "recent_alerts": high_alerts
    }


@app.route("/")
def home():
    return redirect(url_for("dashboard"))


@app.route("/events")
def events():
    events_list = load_events()
    # Sort newest first (simple sort; improve later with real timestamps)
    events_list = sorted(events_list, key=lambda e: e.get("timestamp", ""), reverse=True)
    return render_template("events.html", events=events_list)

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

    # Top 5 zones
    top_zones = sorted(
        stats["zone_counts"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    return render_template(
        "dashboard.html",
        stats=stats,
        top_event_types=top_event_types,
        top_zones=top_zones
    )


if __name__ == "__main__":
    app.run(debug=True)
