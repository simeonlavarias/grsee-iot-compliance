from flask import Flask, render_template, redirect, url_for, Response, jsonify, request
import json
from pathlib import Path
import io
import csv
from datetime import datetime
import threading
import time

import paho.mqtt.client as mqtt

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

# --- MQTT configuration (minimal simulation) ---
MQTT_BROKER_HOST = "127.0.0.1"
MQTT_BROKER_PORT = 1883
MQTT_TOPIC = "grsee/events"
ENABLE_MQTT = True


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
# Incident auto-creation
# -----------------------
def sync_incidents_from_events():
    """
    Auto-create incidents in DB for any DB events that are violations.
    Safe to call multiple times (no duplicates).
    Only runs when events are coming from the database.
    """
    first = Event.query.first()
    if not first:
        return 0

    created = 0
    db_events = Event.query.all()

    for ev in db_events:
        existing = Incident.query.filter_by(event_id_fk=ev.id).first()
        if existing:
            continue

        e_dict = {
            "event_id": ev.event_id,
            "timestamp": ev.timestamp,
            "device_type": ev.device_type,
            "zone": ev.zone,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "summary": ev.summary
        }

        proc = evaluate_event(e_dict)

        if proc["policy_result"]["is_violation"] and proc["incident"].get("create_incident"):
            inc = Incident(
                incident_type=proc["incident"].get("incident_type") or "UNSPECIFIED",
                status="open",
                event_id_fk=ev.id
            )
            db.session.add(inc)
            created += 1

    if created > 0:
        db.session.commit()

    return created


def get_incident_widget_data(limit=5):
    open_count = Incident.query.filter_by(status="open").count()

    recent = (
        Incident.query
        .order_by(Incident.created_at.desc())
        .limit(limit)
        .all()
    )

    recent_list = []
    for inc in recent:
        event_public_id = inc.event.event_id if getattr(inc, "event", None) else None
        recent_list.append({
            "id": inc.id,
            "incident_type": inc.incident_type,
            "status": inc.status,
            "created_at": inc.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "event_id": event_public_id
        })

    return open_count, recent_list


# -----------------------
# MQTT ingestion helpers
# -----------------------
def _upsert_device_for_event(e: dict):
    device_key = f"{e.get('device_type', 'UNKNOWN')}_{e.get('zone', 'UNKNOWN')}"
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
        db.session.flush()
    else:
        device.last_seen = e.get("timestamp")

    return device


def _insert_event_to_db(e: dict):
    eid = e.get("event_id")
    if not eid:
        return False

    exists = Event.query.filter_by(event_id=eid).first()
    if exists:
        return False

    device = _upsert_device_for_event(e)

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
    db.session.commit()
    return True


# -----------------------
# MQTT subscriber (stable)
# -----------------------
def start_mqtt_subscriber():
    print("[MQTT] start_mqtt_subscriber() CALLED")

    if not ENABLE_MQTT:
        print("[MQTT] Disabled.")
        return

    def on_connect(client, userdata, flags, rc):
        print(f"[MQTT] on_connect fired rc={rc}")
        if rc == 0:
            print(f"[MQTT] Connected. Subscribing to {MQTT_TOPIC}")
            client.subscribe(MQTT_TOPIC, qos=1)
        else:
            print(f"[MQTT] Connection failed rc={rc}")

    def on_disconnect(client, userdata, rc):
        print(f"[MQTT] Disconnected rc={rc}")

    def on_message(client, userdata, msg):
        try:
            payload = msg.payload.decode("utf-8")
            e = json.loads(payload)

            with app.app_context():
                inserted = _insert_event_to_db(e)
                if inserted:
                    created = sync_incidents_from_events()
                    print(f"[MQTT] Stored event_id={e.get('event_id')} (incidents created={created})")
                else:
                    print(f"[MQTT] Duplicate/invalid event ignored: {e.get('event_id')}")
        except Exception as ex:
            print("[MQTT] Error processing message:", ex)

    def run():
        client = mqtt.Client(
            client_id=f"grsee-subscriber-{int(time.time())}",
            protocol=mqtt.MQTTv311,
            callback_api_version=mqtt.CallbackAPIVersion.VERSION1
        )

        client.on_connect = on_connect
        client.on_disconnect = on_disconnect
        client.on_message = on_message

        client.enable_logger()  # IMPORTANT: shows connect errors
        client.reconnect_delay_set(min_delay=1, max_delay=10)

        print(f"[MQTT] Connecting to {MQTT_BROKER_HOST}:{MQTT_BROKER_PORT} ...")
        client.connect(MQTT_BROKER_HOST, MQTT_BROKER_PORT, keepalive=60)

        print("[MQTT] connect() called, entering loop_forever() ...")
        client.loop_forever()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    print("[MQTT] Subscriber thread started.")

# -----------------------
# Routes (UI)
# -----------------------
@app.route("/")
def home():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    sync_incidents_from_events()

    events = get_events_source()
    stats = compute_dashboard_stats(events)
    zone_rows = build_zone_rows(events, threshold=THRESHOLD)

    top_event_types = sorted(stats["event_type_counts"].items(), key=lambda x: x[1], reverse=True)[:5]
    top_zones = sorted(stats["zone_counts"].items(), key=lambda x: x[1], reverse=True)[:5]

    open_incidents_count, recent_incidents = get_incident_widget_data(limit=5)

    return render_template(
        "dashboard.html",
        stats=stats,
        top_event_types=top_event_types,
        top_zones=top_zones,
        zone_rows=zone_rows,
        threshold=THRESHOLD,
        open_incidents_count=open_incidents_count,
        recent_incidents=recent_incidents
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
    sync_incidents_from_events()
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
        iso_controls = "; ".join(
            [f'{c.get("control_id")} {c.get("title")}' for c in proc["compliance_mapping"]["iso27001_controls"]]
        )
        pci_reqs = "; ".join(
            [f'{r.get("requirement_id")} {r.get("title")}' for r in proc["compliance_mapping"]["pcidss_requirements"]]
        )

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

            device_key = f"{e.get('device_type', 'UNKNOWN')}_{e.get('zone', 'UNKNOWN')}"
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
                db.session.flush()

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

@app.route("/admin/reset")
def admin_reset():
    Incident.query.delete()
    Event.query.delete()
    Device.query.delete()
    db.session.commit()
    return "Reset complete: cleared Device, Event, Incident."


# -----------------------
# Main
# -----------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    start_mqtt_subscriber()
    app.run(debug=True, use_reloader=False)
