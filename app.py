from flask import Flask, render_template, redirect, url_for, Response, jsonify, request
import json
from pathlib import Path
import io
import csv
from datetime import datetime

from rule_engine import evaluate_event
from models import db, Device, Event, Incident

app = Flask(__name__)

# --- SQLite configuration ---
BASE_DIR = Path(__file__).parent
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{BASE_DIR / 'grsee.db'}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

DATA_PATH = Path(__file__).parent / "data" / "mock_events.json"

THRESHOLD = 90.0  # zone threshold


# -----------------------
# JSON fallback loader
# -----------------------
def load_events_json():
    if not DATA_PATH.exists():
        return []
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


# -----------------------
# DB helpers
# -----------------------
def event_to_dict(e: Event):
    return {
        "event_id": e.event_id,
        "timestamp": e.timestamp,
        "device_type": e.device_type,
        "zone": e.zone,
        "event_type": e.event_type,
        "severity": e.severity,
        "summary": e.summary,
        "payload": json.loads(e.payload_json) if e.payload_json else None
    }


def get_events_source():
    """
    Prefer DB if it has events; otherwise fall back to JSON file.
    Returns list of dict events.
    """
    db_events = Event.query.order_by(Event.timestamp.desc()).all()
    if db_events:
        return [event_to_dict(e) for e in db_events]
    return sorted(load_events_json(), key=lambda e: e.get("timestamp", ""), reverse=True)


def compute_dashboard_stats(events):
    total = len(events)

    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for e in events:
        sev = (e.get("severity") or "").strip().lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    event_type_counts = {}
    for e in events:
        t = e.get("event_type", "UNKNOWN")
        event_type_counts[t] = event_type_counts.get(t, 0) + 1

    zone_counts = {}
    for e in events:
        z = e.get("zone", "UNKNOWN")
        zone_counts[z] = zone_counts.get(z, 0) + 1

    high_alerts = [e for e in events if (e.get("severity", "").lower() in ["high", "critical"])]
    high_alerts = sorted(high_alerts, key=lambda e: e.get("timestamp", ""), reverse=True)[:5]

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
        "violations_count": violations_count,
        "compliant_count": compliant_count,
        "compliance_percent": compliance_percent,
        "violation_percent": violation_percent
    }


def build_zone_rows(events, threshold=THRESHOLD):
    zone_breakdown = {}

    for e in events:
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
        status = "NEEDS_ATTENTION" if compliance_percent < threshold else "WITHIN_THRESHOLD"
        zone_rows.append({
            "zone": zone,
            "total": total,
            "violations": violations,
            "compliance_percent": compliance_percent,
            "status": status
        })

    return sorted(zone_rows, key=lambda r: r["compliance_percent"])


def build_violations_list(events):
    violations = []
    for e in events:
        proc = evaluate_event(e)
        if proc["policy_result"]["is_violation"]:
            violations.append({"raw": e, "proc": proc})
    return sorted(violations, key=lambda v: v["raw"].get("timestamp", ""), reverse=True)


# -----------------------
# Routes (UI)
# -----------------------
@app.route("/")
def home():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    events = get_events_source()
    stats = compute_dashboard_stats(events)
    zone_rows = build_zone_rows(events, threshold=THRESHOLD)

    top_event_types = sorted(stats["event_type_counts"].items(), key=lambda x: x[1], reverse=True)[:5]
    top_zones = sorted(stats["zone_counts"].items(), key=lambda x: x[1], reverse=True)[:5]

    return render_template(
        "dashboard.html",
        stats=stats,
        top_event_types=top_event_types,
        top_zones=top_zones,
        zone_rows=zone_rows,
        threshold=THRESHOLD
    )


@app.route("/events")
def events_page():
    events = get_events_source()

    enriched = []
    for e in events:
        result = evaluate_event(e)
        status = "VIOLATION" if result["policy_result"]["is_violation"] else "COMPLIANT"
        enriched.append({**e, "compliance_status": status})

    return render_template("events.html", events=enriched)


@app.route("/violations")
def violations_page():
    events = get_events_source()
    violations_only = build_violations_list(events)
    return render_template("violations.html", violations=violations_only)


@app.route("/event/<event_id>")
def event_detail(event_id):
    events = get_events_source()
    target = next((e for e in events if e.get("event_id") == event_id), None)

    if target is None:
        return render_template("event_detail.html", found=False, event_id=event_id)

    processed = evaluate_event(target)
    return render_template("event_detail.html", found=True, raw=target, proc=processed)


# -----------------------
# Report download (CSV)
# -----------------------
@app.route("/report.csv")
def report_csv():
    events = get_events_source()
    stats = compute_dashboard_stats(events)
    zone_rows = build_zone_rows(events, threshold=THRESHOLD)
    violations = build_violations_list(events)

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["GRSee Audit Report (Prototype)"])
    writer.writerow(["Generated at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    writer.writerow(["Threshold (%)", THRESHOLD])
    writer.writerow([])

    writer.writerow(["Summary"])
    writer.writerow(["Total events", stats["total"]])
    writer.writerow(["Compliant events", stats["compliant_count"]])
    writer.writerow(["Violation events", stats["violations_count"]])
    writer.writerow(["Compliance (%)", stats["compliance_percent"]])
    writer.writerow(["Violation (%)", stats["violation_percent"]])
    writer.writerow([])

    writer.writerow(["Compliance by Zone"])
    writer.writerow(["Zone", "Total Events", "Violations", "Compliance (%)", "Status"])
    for z in zone_rows:
        writer.writerow([z["zone"], z["total"], z["violations"], z["compliance_percent"], z["status"]])
    writer.writerow([])

    writer.writerow(["Violations"])
    writer.writerow(["Event ID", "Timestamp", "Zone", "Device", "Event Type", "Severity",
                     "Policy", "Reason", "ISO Controls", "PCI Requirements", "Incident Suggested"])

    for v in violations:
        raw = v["raw"]
        proc = v["proc"]
        iso_controls = "; ".join([f'{c.get("control_id")} {c.get("title")}' for c in proc["compliance_mapping"]["iso27001_controls"]])
        pci_reqs = "; ".join([f'{r.get("requirement_id")} {r.get("title")}' for r in proc["compliance_mapping"]["pcidss_requirements"]])

        writer.writerow([
            raw.get("event_id"),
            raw.get("timestamp"),
            raw.get("zone"),
            raw.get("device_type"),
            raw.get("event_type"),
            raw.get("severity"),
            proc["policy_result"].get("policy_name"),
            proc["policy_result"].get("reason"),
            iso_controls,
            pci_reqs,
            proc["incident"].get("incident_type") if proc["incident"].get("create_incident") else ""
        ])

    csv_data = output.getvalue()
    output.close()

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=grsee_audit_report.csv"}
    )


# -----------------------
# Admin: init DB + seed from JSON
# -----------------------
@app.route("/admin/init-db")
def init_db():
    with app.app_context():
        db.create_all()
    return "DB initialized (tables created)."


@app.route("/admin/seed")
def seed_db_from_json():
    """
    Imports events from data/mock_events.json into SQLite.
    Safe to run multiple times (skips existing event_id).
    """
    with app.app_context():
        db.create_all()

        events = load_events_json()
        inserted = 0
        skipped = 0

        for e in events:
            eid = e.get("event_id")
            if not eid:
                continue

            exists = Event.query.filter_by(event_id=eid).first()
            if exists:
                skipped += 1
                continue

            # Create/find device entry (very simple)
            device_key = f"{e.get('device_type','UNKNOWN')}_{e.get('zone','UNKNOWN')}"
            device = Device.query.filter_by(device_id=device_key).first()
            if not device:
                device = Device(
                    device_id=device_key,
                    device_type=e.get("device_type", "UNKNOWN"),
                    zone=e.get("zone", "UNKNOWN"),
                    status="active",
                    last_seen=e.get("timestamp")
                )
                db.session.add(device)
                db.session.flush()  # so device.id is available

            ev = Event(
                event_id=eid,
                device_id_fk=device.id,
                timestamp=e.get("timestamp", ""),
                device_type=e.get("device_type", ""),
                zone=e.get("zone", ""),
                event_type=e.get("event_type", ""),
                severity=e.get("severity", ""),
                summary=e.get("summary", ""),
                payload_json=json.dumps(e, ensure_ascii=False)
            )
            db.session.add(ev)
            inserted += 1

        db.session.commit()

    return f"Seed complete. Inserted={inserted}, Skipped(existing)={skipped}"


# -----------------------
# API Endpoints (MVP)
# -----------------------
@app.route("/api/events", methods=["GET"])
def api_events():
    """
    Returns events from DB if available (else JSON fallback).
    Query params:
      - limit (default 100)
    """
    limit = int(request.args.get("limit", "100"))
    events = get_events_source()[:limit]
    return jsonify({"count": len(events), "events": events})


@app.route("/api/dashboard", methods=["GET"])
def api_dashboard():
    events = get_events_source()
    stats = compute_dashboard_stats(events)
    zone_rows = build_zone_rows(events, threshold=THRESHOLD)
    return jsonify({"stats": stats, "zone_rows": zone_rows, "threshold": THRESHOLD})


@app.route("/api/violations", methods=["GET"])
def api_violations():
    events = get_events_source()
    violations = build_violations_list(events)
    # return simplified payload
    out = []
    for v in violations:
        raw = v["raw"]
        proc = v["proc"]
        out.append({
            "event": raw,
            "policy": proc["policy_result"],
            "incident": proc["incident"],
            "compliance_mapping": proc["compliance_mapping"]
        })
    return jsonify({"count": len(out), "violations": out})


@app.route("/api/incidents", methods=["GET"])
def api_incidents():
    """
    Incidents table is ready, but we only return what exists for now.
    """
    incidents = Incident.query.order_by(Incident.created_at.desc()).all()
    out = []
    for i in incidents:
        out.append({
            "id": i.id,
            "incident_type": i.incident_type,
            "status": i.status,
            "event_id": i.event.event_id if i.event_id_fk and i.event else None,
            "created_at": i.created_at.isoformat()
        })
    return jsonify({"count": len(out), "incidents": out})


if __name__ == "__main__":
    app.run(debug=True)
