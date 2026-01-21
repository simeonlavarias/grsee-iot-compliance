import json
import time
import random
import uuid
from datetime import datetime
import paho.mqtt.client as mqtt

BROKER_HOST = "127.0.0.1"
BROKER_PORT = 1883
TOPIC = "grsee/events"

ZONES = ["SERVER_ROOM", "LOBBY", "CASH_VAULT"]

def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def build_event(i: int):
    zone = random.choice(ZONES)
    event_type = random.choice([
        "MOTION_DETECTED",
        "RFID_ACCESS_GRANTED",
        "RFID_ACCESS_DENIED",
        "TEMP_THRESHOLD_EXCEEDED",
        "CAMERA_TAMPER_DETECTED"
    ])

    base = {
        "event_id": f"mqtt_evt_{uuid.uuid4()}",
        "timestamp": now_ts(),
        "device_type": "MQTT_SIM",
        "zone": zone,
        "event_type": event_type,
        "severity": "LOW",
        "summary": f"{event_type} detected in {zone}"
    }

    if event_type == "RFID_ACCESS_DENIED":
        base["device_type"] = "RFID"
        base["severity"] = "HIGH"
        base["denied_attempts"] = random.choice([1, 2, 3, 4])

    if event_type == "RFID_ACCESS_GRANTED":
        base["device_type"] = "RFID"
        base["severity"] = "MEDIUM"

    if event_type == "TEMP_THRESHOLD_EXCEEDED":
        base["device_type"] = "TEMP"
        base["severity"] = "HIGH"
        base["temperature"] = random.choice([31.0, 33.5, 35.0]) if zone == "SERVER_ROOM" else random.choice([24.0, 25.0])

    if event_type == "CAMERA_TAMPER_DETECTED":
        base["device_type"] = "CAMERA"
        base["severity"] = "CRITICAL"

    if event_type == "MOTION_DETECTED":
        base["device_type"] = "PIR"
        base["severity"] = "MEDIUM"

    return base

def main():
    # UNIQUE client_id prevents rc=7 disconnects from Mosquitto
    client = mqtt.Client(
        client_id=f"grsee-publisher-{int(time.time())}",
        protocol=mqtt.MQTTv311,
        callback_api_version=mqtt.CallbackAPIVersion.VERSION1
    )

    client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    client.loop_start()

    print(f"[PUBLISHER] Connected. Publishing to '{TOPIC}'")

    i = 0
    try:
        while True:
            event = build_event(i)
            payload = json.dumps(event)
            client.publish(TOPIC, payload, qos=1)
            print("[PUBLISHER] Sent:", payload)
            i += 1
            time.sleep(2)
    except KeyboardInterrupt:
        print("[PUBLISHER] Stopped.")
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    main()
