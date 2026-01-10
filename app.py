from flask import Flask, render_template
import json
from pathlib import Path

app = Flask(__name__)

DATA_PATH = Path(__file__).parent / "data" / "mock_events.json"


def load_events():
    if not DATA_PATH.exists():
        return []
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@app.route("/")
def home():
    return "<h2>GRSee is running. </h2><p>Go to <a href='/events'>/events</a></p>"


@app.route("/events")
def events():
    events_list = load_events()
    # Sort newest first (simple sort; improve later with real timestamps)
    events_list = sorted(events_list, key=lambda e: e.get("timestamp", ""), reverse=True)
    return render_template("events.html", events=events_list)


if __name__ == "__main__":
    app.run(debug=True)
