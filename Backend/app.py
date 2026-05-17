from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO
from flask import send_file

from database.mongodb import threats_collection

import pandas as pd
import random
import threading
import time

app = Flask(__name__)

CORS(app)

socketio = SocketIO(
    app,
    cors_allowed_origins="*"
)

# Fake Threat Types
threats = [
    "SQL Injection Attempt",
    "Port Scanning",
    "Brute Force Login",
    "Malware Activity",
    "Unauthorized Access",
    "DDoS Activity",
]

# Generate Live Threats
def generate_threats():

    while True:

        threat = {
            "type": random.choice(threats),

            "ip": f"{random.randint(1,255)}."
                  f"{random.randint(1,255)}."
                  f"{random.randint(1,255)}."
                  f"{random.randint(1,255)}",

            "severity": random.choice(
                ["CRITICAL", "HIGH", "MEDIUM"]
            ),

            "time": "Just now",
        }

        # Save to MongoDB
        threats_collection.insert_one(threat)

        # Emit to Frontend
        socketio.emit(
            "new_threat",
            threat
        )

        time.sleep(5)

# Background Thread
thread = threading.Thread(
    target=generate_threats
)

thread.daemon = True
thread.start()

# Home Route
@app.route("/")
def home():

    return {
        "message": "GuardianNode Backend Running"
    }

# Fetch Threat History
@app.route("/api/threats")
def get_threats():

    threats = list(
        threats_collection.find(
            {},
            {"_id": 0}
        )
    )

    return threats[::-1]

# Dashboard Stats API
@app.route("/api/stats")
def get_stats():

    total_threats = threats_collection.count_documents({})

    critical_threats = threats_collection.count_documents(
        {"severity": "CRITICAL"}
    )

    high_threats = threats_collection.count_documents(
        {"severity": "HIGH"}
    )

    medium_threats = threats_collection.count_documents(
        {"severity": "MEDIUM"}
    )

    return {
        "total_threats": total_threats,
        "critical_threats": critical_threats,
        "high_threats": high_threats,
        "medium_threats": medium_threats,
    }

# CSV Export
@app.route("/api/export/csv")
def export_csv():

    threats = list(
        threats_collection.find(
            {},
            {"_id": 0}
        )
    )

    df = pd.DataFrame(threats)

    file_path = "threat_report.csv"

    df.to_csv(
        file_path,
        index=False
    )

    return send_file(
        file_path,
        as_attachment=True
    )

# JSON Export
@app.route("/api/export/json")
def export_json():

    threats = list(
        threats_collection.find(
            {},
            {"_id": 0}
        )
    )

    file_path = "threat_report.json"

    pd.DataFrame(threats).to_json(
        file_path,
        orient="records",
        indent=4
    )

    return send_file(
        file_path,
        as_attachment=True
    )

# Run Server
if __name__ == "__main__":

    socketio.run(
        app,
        debug=False,
        port=5000
    )