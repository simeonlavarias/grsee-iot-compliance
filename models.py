from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(30), nullable=False, default="auditor")  # admin/auditor
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Device(db.Model):
    __tablename__ = "devices"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), unique=True, nullable=False)   # e.g., "RFID_01"
    device_type = db.Column(db.String(64), nullable=False)              # RFID, PIR, TEMP, CCTV
    zone = db.Column(db.String(64), nullable=False)                     # SERVER_ROOM, LOBBY, CASH_VAULT
    status = db.Column(db.String(20), default="active", nullable=False) # active/inactive
    last_seen = db.Column(db.String(64), nullable=True)                 # keep as string for MVP

    events = db.relationship("Event", backref="device", lazy=True)


class Event(db.Model):
    __tablename__ = "events"
    id = db.Column(db.Integer, primary_key=True)

    # Keep original event_id from your JSON so links still work:
    event_id = db.Column(db.String(64), unique=True, nullable=False)

    device_id_fk = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=True)

    timestamp = db.Column(db.String(64), nullable=False)
    device_type = db.Column(db.String(64), nullable=False)
    zone = db.Column(db.String(64), nullable=False)

    event_type = db.Column(db.String(64), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    summary = db.Column(db.String(255), nullable=True)

    # Store raw payload as JSON string (MVP)
    payload_json = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Policy(db.Model):
    __tablename__ = "policies"
    id = db.Column(db.Integer, primary_key=True)
    policy_id = db.Column(db.String(64), unique=True, nullable=False)  # e.g., POL-PA-001
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=True)
    enabled = db.Column(db.Boolean, default=True, nullable=False)


class ComplianceMapping(db.Model):
    """
    Maps event_type to external compliance references.
    Keep it simple: one record per mapping row.
    """
    __tablename__ = "compliance_mappings"
    id = db.Column(db.Integer, primary_key=True)

    event_type = db.Column(db.String(64), nullable=False)

    standard = db.Column(db.String(20), nullable=False)   # "ISO27001" or "PCI_DSS"
    control_id = db.Column(db.String(64), nullable=False) # e.g. "A.11.1.2" or "Req. 9"
    title = db.Column(db.String(255), nullable=False)


class Incident(db.Model):
    __tablename__ = "incidents"
    id = db.Column(db.Integer, primary_key=True)

    incident_type = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(20), default="open", nullable=False)  # open/ack/resolved

    event_id_fk = db.Column(db.Integer, db.ForeignKey("events.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Report(db.Model):
    __tablename__ = "reports"
    id = db.Column(db.Integer, primary_key=True)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    format = db.Column(db.String(20), default="csv", nullable=False)   # csv/pdf
    notes = db.Column(db.String(255), nullable=True)
