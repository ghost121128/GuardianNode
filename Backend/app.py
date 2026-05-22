from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
from pymongo import MongoClient

from datetime import datetime

import random
import threading
import time
import psutil
import requests
import os

# =========================
# Flask App
# =========================

app = Flask(__name__)

CORS(app)

# =========================
# SocketIO
# =========================

socketio = SocketIO(

    app,

    cors_allowed_origins="*"

)

# =========================
# MongoDB Connection
# =========================

MONGO_URI = os.environ.get("MONGO_URI")

if not MONGO_URI:

    raise Exception(
        "MONGO_URI not found"
    )

client = MongoClient(MONGO_URI)

db = client["guardiannode"]

threat_collection = db["threat_logs"]

blocked_collection = db["blocked_ips"]

# =========================
# Threat Simulation Data
# =========================

attack_types = [

    "DDoS Attack",

    "Brute Force",

    "Port Scan",

    "Malware Traffic",

    "SQL Injection",

    "Suspicious Login",

]

severity_levels = [

    "Low",

    "Medium",

    "High",

    "Critical",

]

# =========================
# Random Public IP Generator
# =========================

def generate_random_ip():

    first_octet = random.choice([

        8,
        23,
        45,
        66,
        91,
        103,
        117,
        142,
        151,
        185,
        197,

    ])

    return ".".join([

        str(first_octet),

        str(random.randint(1, 255)),

        str(random.randint(1, 255)),

        str(random.randint(1, 255))

    ])

# =========================
# IP Geolocation
# =========================

def get_ip_location(ip):

    try:

        response = requests.get(

            f"http://ip-api.com/json/{ip}",

            timeout=3

        )

        data = response.json()

        if data["status"] == "success":

            return {

                "country":
                data.get(
                    "country",
                    "Unknown"
                ),

                "city":
                data.get(
                    "city",
                    "Unknown"
                ),

                "lat":
                data.get(
                    "lat",
                    0
                ),

                "lon":
                data.get(
                    "lon",
                    0
                ),

            }

    except Exception as error:

        print(
            "Geolocation Error:",
            error
        )

    return {

        "country":
        "Unknown",

        "city":
        "Unknown",

        "lat":
        0,

        "lon":
        0,

    }

# =========================
# Threat Simulation Engine
# =========================

def simulate_threats():

    while True:

        severity = random.choice(
            severity_levels
        )

        ip_address = (
            generate_random_ip()
        )

        # =========================
        # Geolocation Lookup
        # =========================

        location = (
            get_ip_location(
                ip_address
            )
        )

        # =========================
        # Default Status
        # =========================

        status = "Monitoring"

        # =========================
        # IPS Auto Blocking
        # =========================

        if severity == "Critical":

            status = "Blocked"

            blocked_collection.insert_one({

                "ip":
                ip_address,

                "reason":
                "Critical Threat",

                "country":
                location["country"],

                "city":
                location["city"],

                "timestamp":
                datetime.now(),

            })

            print(
                f"[IPS] Blocking IP {ip_address}"
            )

        # =========================
        # Threat Object
        # =========================

        threat = {

            "ip":
            ip_address,

            "type":
            random.choice(
                attack_types
            ),

            "severity":
            severity,

            "status":
            status,

            "country":
            location["country"],

            "city":
            location["city"],

            "lat":
            location["lat"],

            "lon":
            location["lon"],

            "timestamp":
            datetime.now(),

        }

        # =========================
        # Save Threat
        # =========================

        threat_collection.insert_one(
            threat
        )

        # =========================
        # Emit Live Threat
        # =========================

        socketio.emit(

            "new_threat",

            {

                "ip":
                threat["ip"],

                "type":
                threat["type"],

                "severity":
                threat["severity"],

                "status":
                threat["status"],

                "country":
                threat["country"],

                "city":
                threat["city"],

                "lat":
                threat["lat"],

                "lon":
                threat["lon"],

            }

        )

        print(
            "Threat Generated:",
            threat
        )

        time.sleep(5)

# =========================
# Home Route
# =========================

@app.route("/")
def home():

    return jsonify({

        "message":
        "GuardianNode Backend Running"

    })

# =========================
# REAL THREAT API
# =========================

@app.route(
    "/api/add-threat",
    methods=["POST"]
)
def add_threat():

    data = request.json

    if not data:

        return jsonify({
            "error": "No data"
        }), 400

    ip_address = data.get(
        "ip",
        "Unknown"
    )

    # =========================
    # Get Location
    # =========================

    location = get_ip_location(
        ip_address
    )

    threat = {

        "ip":
        ip_address,

        "type":
        data.get(
            "type",
            "Unknown Threat"
        ),

        "severity":
        data.get(
            "severity",
            "Medium"
        ),

        "status":
        data.get(
            "status",
            "Monitoring"
        ),

        "country":
        location["country"],

        "city":
        location["city"],

        "lat":
        location["lat"],

        "lon":
        location["lon"],

        "timestamp":
        datetime.now(),

    }

    # =========================
    # Save Threat
    # =========================

    threat_collection.insert_one(
        threat
    )

    # =========================
    # Save Blocked IP
    # =========================

    if threat["status"] == "Blocked":

        blocked_collection.insert_one({

            "ip":
            threat["ip"],

            "reason":
            threat["type"],

            "country":
            threat["country"],

            "city":
            threat["city"],

            "timestamp":
            datetime.now(),

        })

    # =========================
    # Emit Socket Event
    # =========================

    socketio.emit(

        "new_threat",

        {

            "ip":
            threat["ip"],

            "type":
            threat["type"],

            "severity":
            threat["severity"],

            "status":
            threat["status"],

            "country":
            threat["country"],

            "city":
            threat["city"],

            "lat":
            threat["lat"],

            "lon":
            threat["lon"],

        }

    )

    print(
        "[REAL THREAT]",
        threat
    )

    return jsonify({

        "message":
        "Threat Added"

    })

# =========================
# Get All Threats
# =========================

@app.route("/threats")
def get_threats():

    threats = []

    for threat in threat_collection.find().sort(
        "timestamp",
        -1
    ):

        threats.append({

            "ip":
            threat.get("ip"),

            "type":
            threat.get("type"),

            "severity":
            threat.get("severity"),

            "status":
            threat.get("status"),

            "country":
            threat.get("country"),

            "city":
            threat.get("city"),

            "lat":
            threat.get("lat"),

            "lon":
            threat.get("lon"),

            "timestamp":
            str(
                threat.get(
                    "timestamp"
                )
            )

        })

    return jsonify(threats)

# =========================
# Dashboard Analytics API
# =========================

@app.route("/dashboard-stats")
def dashboard_stats():

    total_threats = (
        threat_collection.count_documents({})
    )

    critical_alerts = (
        threat_collection.count_documents({
            "severity": "Critical"
        })
    )

    blocked_attacks = (
        threat_collection.count_documents({
            "status": "Blocked"
        })
    )

    monitoring_count = (
        threat_collection.count_documents({
            "status": "Monitoring"
        })
    )

    return jsonify({

        "totalThreats":
        total_threats,

        "criticalAlerts":
        critical_alerts,

        "blockedAttacks":
        blocked_attacks,

        "monitoringCount":
        monitoring_count,

    })

# =========================
# Blocked IPs API
# =========================

@app.route("/blocked-ips")
def blocked_ips():

    blocked = []

    for ip in blocked_collection.find().sort(
        "timestamp",
        -1
    ):

        blocked.append({

            "ip":
            ip.get("ip"),

            "reason":
            ip.get("reason"),

            "country":
            ip.get("country"),

            "city":
            ip.get("city"),

            "timestamp":
            str(
                ip.get(
                    "timestamp"
                )
            )

        })

    return jsonify(blocked)

# =========================
# System Metrics API
# =========================

@app.route("/system-metrics")
def system_metrics():

    cpu = psutil.cpu_percent()

    ram = psutil.virtual_memory().percent

    disk = psutil.disk_usage("/").percent

    uptime = time.time() - psutil.boot_time()

    uptime_hours = round(
        uptime / 3600,
        1
    )

    return jsonify({

        "cpu":
        cpu,

        "ram":
        ram,

        "disk":
        disk,

        "uptime":
        uptime_hours,

    })

# =========================
# Start Threat Simulation
# =========================

simulation_thread = threading.Thread(
    target=simulate_threats
)

simulation_thread.daemon = True

simulation_thread.start()

# =========================
# Run Server
# =========================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    socketio.run(

        app,

        host="0.0.0.0",

        port=port,

        debug=False,

        use_reloader=False

    )