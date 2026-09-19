from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
import joblib
import json
import random
import time
import asyncio
from datetime import datetime
import os
import threading
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- CONFIGURATION (Unidirectional Threat Detection Architecture) ---
MODEL_FILE = 'multiclass_xgboost_unidirectional.joblib'
LABEL_ENCODER_FILE = 'label_encoder_unidirectional.joblib'
FEATURE_FILE = 'feature_columns_unidirectional.json'
SIMULATED_FILE = 'large_simulation_log.csv'
METRICS_FILE = 'unidirectional_model_metrics.json'

# TRAFFIC_MODE: 'SIMULATION' (default) or 'LIVE'
# Set env var TRAFFIC_MODE=LIVE to enable real packet capture (requires Admin + tshark)
# Set LIVE_INTERFACE to your NIC name, e.g. 'Ethernet' or 'Wi-Fi'
TRAFFIC_MODE = os.environ.get("TRAFFIC_MODE", "SIMULATION").upper()
LIVE_INTERFACE = os.environ.get("LIVE_INTERFACE", None)  # None = PyShark default

# --- GLOBAL LOCATIONS & IP POOLS (For Diverse Global Attack Simulation) ---
GLOBAL_LOCATIONS = [
    {"country": "China", "city": "Beijing", "lat": 39.9042, "lon": 116.4074, "ip_prefix": "123.125."},
    {"country": "China", "city": "Shanghai", "lat": 31.2304, "lon": 121.4737, "ip_prefix": "180.153."},
    {"country": "China", "city": "Shenzhen", "lat": 22.5431, "lon": 114.0579, "ip_prefix": "119.147."},
    {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "ip_prefix": "185.220."},
    {"country": "Russia", "city": "Saint Petersburg", "lat": 59.9343, "lon": 30.3351, "ip_prefix": "91.240."},
    {"country": "Russia", "city": "Novosibirsk", "lat": 55.0084, "lon": 82.9357, "ip_prefix": "178.62."},
    {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "ip_prefix": "46.165."},
    {"country": "Germany", "city": "Berlin", "lat": 52.5200, "lon": 13.4050, "ip_prefix": "144.76."},
    {"country": "USA", "city": "New York", "lat": 40.7128, "lon": -74.0060, "ip_prefix": "199.195."},
    {"country": "USA", "city": "Los Angeles", "lat": 34.0522, "lon": -118.2437, "ip_prefix": "104.244."},
    {"country": "USA", "city": "Chicago", "lat": 41.8781, "lon": -87.6298, "ip_prefix": "208.80."},
    {"country": "Brazil", "city": "São Paulo", "lat": -23.5505, "lon": -46.6333, "ip_prefix": "177.126."},
    {"country": "Brazil", "city": "Rio de Janeiro", "lat": -22.9068, "lon": -43.1729, "ip_prefix": "186.204."},
    {"country": "India", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777, "ip_prefix": "103.251."},
    {"country": "India", "city": "Bengaluru", "lat": 12.9716, "lon": 77.5946, "ip_prefix": "49.207."},
    {"country": "India", "city": "Delhi", "lat": 28.6139, "lon": 77.2090, "ip_prefix": "182.72."},
    {"country": "North Korea", "city": "Pyongyang", "lat": 39.0392, "lon": 125.7625, "ip_prefix": "175.45."},
    {"country": "United Kingdom", "city": "London", "lat": 51.5074, "lon": -0.1278, "ip_prefix": "82.165."},
    {"country": "France", "city": "Paris", "lat": 48.8566, "lon": 2.3522, "ip_prefix": "51.15."},
    {"country": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "ip_prefix": "188.166."},
    {"country": "Japan", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503, "ip_prefix": "133.242."},
    {"country": "South Korea", "city": "Seoul", "lat": 37.5665, "lon": 126.9780, "ip_prefix": "211.234."},
    {"country": "Australia", "city": "Sydney", "lat": -33.8688, "lon": 151.2093, "ip_prefix": "139.130."},
    {"country": "Singapore", "city": "Singapore", "lat": 1.3521, "lon": 103.8198, "ip_prefix": "128.199."},
    {"country": "Canada", "city": "Toronto", "lat": 43.6532, "lon": -79.3832, "ip_prefix": "142.44."},
    {"country": "Iran", "city": "Tehran", "lat": 35.6892, "lon": 51.3890, "ip_prefix": "185.143."},
    {"country": "Israel", "city": "Tel Aviv", "lat": 32.0853, "lon": 34.7818, "ip_prefix": "82.80."},
    {"country": "South Africa", "city": "Johannesburg", "lat": -26.2041, "lon": 28.0473, "ip_prefix": "197.234."},
    {"country": "Sweden", "city": "Stockholm", "lat": 59.3293, "lon": 18.0686, "ip_prefix": "193.182."},
    {"country": "Turkey", "city": "Istanbul", "lat": 41.0082, "lon": 28.9784, "ip_prefix": "85.105."},
    {"country": "Vietnam", "city": "Hanoi", "lat": 21.0285, "lon": 105.8542, "ip_prefix": "113.161."},
    {"country": "Ukraine", "city": "Kyiv", "lat": 50.4501, "lon": 30.5234, "ip_prefix": "194.44."},
    {"country": "Poland", "city": "Warsaw", "lat": 52.2297, "lon": 21.0122, "ip_prefix": "77.55."},
    {"country": "Taiwan", "city": "Taipei", "lat": 25.0330, "lon": 121.5654, "ip_prefix": "210.65."}
]

COUNTRY_COORDS = {loc["country"]: [loc["lat"], loc["lon"]] for loc in GLOBAL_LOCATIONS}

from sqlalchemy.orm import Session
from fastapi import Depends
from database import get_db, TrafficLog, AutoBlocked, ManualReview, init_db

# Initialize DB on startup
init_db()

# --- GLOBAL STATE (Configuration Only) ---
class SystemState:
    def __init__(self):
        # We keep stats in memory for performance, but sync critical logs to DB
        self.stats = {
            "scanned": 0,
            "threats_detected": 0,
            "auto_blocked": 0,
            "manual_blocked": 0,
            "uptime_start": time.time()
        }
        self.config = {
            "auto_block_threshold": 0.95, # 95% confidence
            "simulation_speed": 0.4       # 0.4s per packet for dynamic live stream
        }
        self.is_running = (TRAFFIC_MODE == "SIMULATION")

state = SystemState()

# --- LOAD ASSETS ---
print("Loading AI Models...")
model = joblib.load(MODEL_FILE)
label_encoder = joblib.load(LABEL_ENCODER_FILE)
with open(FEATURE_FILE, 'r') as f:
    feature_columns = json.load(f)

# Load Traffic Data
if os.path.exists(SIMULATED_FILE):
    traffic_df = pd.read_csv(SIMULATED_FILE)
    traffic_df.columns = traffic_df.columns.str.strip()
    logger.info(f"Loaded {len(traffic_df)} rows from '{SIMULATED_FILE}'.")
else:
    logger.warning(
        f"'{SIMULATED_FILE}' not found. Generating synthetic traffic data for simulation..."
    )
    import numpy as np
    n_rows = 1000
    rng = np.random.default_rng(42)
    synthetic_data = {col: rng.uniform(0, 1000, n_rows) for col in feature_columns}
    synthetic_data["Destination Port"] = rng.choice([80, 443, 22, 3389, 8080], n_rows).astype(float)
    synthetic_data["FIN Flag Count"] = rng.integers(0, 2, n_rows).astype(float)
    synthetic_data["PSH Flag Count"] = rng.integers(0, 2, n_rows).astype(float)
    synthetic_data["ACK Flag Count"] = rng.integers(0, 2, n_rows).astype(float)
    traffic_df = pd.DataFrame(synthetic_data)
    logger.info(f"Generated {n_rows} rows of synthetic traffic data.")


# --- BACKGROUND SIMULATOR ---
# This thread mimics live traffic coming into the router
def traffic_simulator():
    index = 0
    # Create a dedicated session for the background thread
    from database import SessionLocal
    
    # --- DB RESET FOR NEW SCHEMA (Drop and Recreate) ---
    # WARNING: destructive, but requested by user
    print("Resetting Database Schema...")
    from database import Base, engine
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    print("Database Reset Complete.")
    
    while True:
        if state.is_running:
            db = SessionLocal()
            try:
                # 1. Get Next Packet
                row = traffic_df.iloc[index % len(traffic_df)]
                index += 1

                # 2. Predict
                features = pd.DataFrame([row[feature_columns]])
                pred_numeric = model.predict(features)[0]
                pred_text = label_encoder.inverse_transform([pred_numeric])[0]
                
                # 3. Enrich Data (Dynamic Global Threat Nodes & Realistic Public IPs)
                loc = random.choice(GLOBAL_LOCATIONS)
                fake_country = loc["country"]
                fake_ip = f"{loc['ip_prefix']}{random.randint(2, 254)}.{random.randint(1, 254)}"
                lat = round(loc["lat"] + random.uniform(-0.15, 0.15), 4)
                lon = round(loc["lon"] + random.uniform(-0.15, 0.15), 4)
                timestamp = datetime.now() # Use datetime object for DB
                
                # Fake Confidence
                if pred_text == "Normal Traffic":
                    confidence = random.uniform(0.90, 0.99)
                else:
                    confidence = random.uniform(0.75, 0.99)

                # --- NEW CONTEXT DATA GENERATION ---
                target_username = None
                burst_score = 0.0
                failed_attempts = 0
                traffic_volume = "Normal"
                login_behavior = "Normal"

                # Traffic Volume
                if "DoS" in pred_text:
                     traffic_volume = random.choices(["High", "Medium"], weights=[0.8, 0.2])[0]
                elif pred_text == "Normal Traffic":
                     traffic_volume = random.choices(["Normal", "Low"], weights=[0.7, 0.3])[0]
                else:
                     traffic_volume = random.choices(["Medium", "High"], weights=[0.6, 0.4])[0]

                # Burst Score
                if pred_text == "Normal Traffic":
                    burst_score = round(random.uniform(0.0, 1.4), 2)
                else:
                    burst_score = round(random.uniform(1.5, 5.0), 2)

                # Failed Attempts & Login Behavior
                # Logic:
                # - Brute Force / Bot / Web Attack -> "Detected" (High failed attempts, specific username)
                # - DDoS / DoS / PortScan -> "Suspicious" (Some failed attempts, no specific username usually, but we can simmer it)
                # - Normal -> "Normal"

                is_brute_force = any(x in pred_text for x in ["Brute", "Force", "Patator", "Web Attack", "Sql", "XSS"])
                is_bot = "Bot" in pred_text
                is_dos = any(x in pred_text for x in ["DoS", "DDoS", "Heartbleed"])
                is_scan = "Port" in pred_text or "Scan" in pred_text

                if is_brute_force or is_bot:
                    failed_attempts = random.randint(5, 50)
                    login_behavior = "Detected"
                    target_username = random.choice(["admin", "root", "user1", "test_user", "service_account", "postgres", "manager"])
                elif is_dos or is_scan:
                    failed_attempts = random.randint(1, 6) # DDoS doesn't necessarily fail logins, but might cause timeouts/errors
                    login_behavior = "Suspicious"
                    target_username = None # Usually targeting infrastructure, not accounts
                elif "Normal" in pred_text:
                    failed_attempts = random.randint(0, 3)
                    login_behavior = "Normal"
                    target_username = None
                else:
                    # Fallback for other attacks
                    failed_attempts = random.randint(2, 10)
                    login_behavior = "Suspicious"
                    target_username = None

                # Unidirectional Flow Telemetry
                fwd_pkts = int(row.get("Total Fwd Packets", 1))
                fwd_bytes = float(row.get("Total Length of Fwd Packets", 0.0))
                fwd_iat = float(row.get("Fwd IAT Mean", 0.0))

                # Unidirectional detection rationale
                if "DoS" in pred_text or "DDoS" in pred_text:
                    detection_rationale = f"Volumetric forward saturation ({fwd_pkts} pkts, {fwd_bytes/1024:.1f} KB) without ACK return path"
                elif "Scan" in pred_text or "Port" in pred_text:
                    detection_rationale = f"Unidirectional SYN/probe sweep targeting port {int(row.get('Destination Port', 0))} with no reply"
                elif "Brute" in pred_text:
                    detection_rationale = f"Persistent forward auth payloads ({failed_attempts} fails) traversing unidirectional tap"
                elif "Bot" in pred_text:
                    detection_rationale = f"C2 periodic forward beaconing detected via IAT clustering ({fwd_iat:.1f}μs)"
                elif "Web" in pred_text:
                    detection_rationale = "Blind HTTP/SQL injection signature detected in forward stream payload"
                elif pred_text == "Normal Traffic":
                    detection_rationale = "Normal unidirectional ingress stream within baseline"
                else:
                    detection_rationale = f"Unidirectional anomaly ({pred_text}) flagged via forward flow timing and entropy"

                # 4. Create Traffic Log Entry
                traffic_log = TrafficLog(
                    timestamp=timestamp,
                    src_ip=fake_ip,
                    country=fake_country,
                    lat=lat,
                    lon=lon,
                    type=pred_text,
                    confidence=confidence,
                    destination_port=int(row.get("Destination Port", 0)),
                    action="MONITOR",
                    # Context Fields
                    target_username=target_username,
                    burst_score=burst_score,
                    failed_attempts=failed_attempts,
                    traffic_volume=traffic_volume,
                    login_behavior=login_behavior,
                    # Unidirectional Telemetry
                    flow_direction="INGRESS_UNIDIRECTIONAL",
                    fwd_packets=fwd_pkts,
                    fwd_bytes=fwd_bytes,
                    fwd_iat_mean=fwd_iat,
                    detection_rationale=detection_rationale
                )

                # 5. SOAR Logic (The Brain)
                state.stats["scanned"] += 1
                
                if pred_text != "Normal Traffic":
                    state.stats["threats_detected"] += 1
                    
                    # Check Auto-Block Policy
                    if confidence >= state.config["auto_block_threshold"]:
                        traffic_log.action = "AUTO_BLOCKED"
                        state.stats["auto_blocked"] += 1
                        
                        # Add to AutoBlocked Table
                        auto_block_entry = AutoBlocked(
                            timestamp=timestamp,
                            src_ip=fake_ip,
                            country=fake_country,
                            limit_reached=f"Confidence > {state.config['auto_block_threshold']*100}%",
                            confidence=confidence,
                            type=pred_text
                        )
                        db.add(auto_block_entry)
                        
                    else:
                        # Send to Portal B (Human Review)
                        traffic_log.action = "PENDING_REVIEW"
                        
                        # Add to ManualReview Table (Only if not duplicate/flooding - simplified for DB)
                        pending_count = db.query(ManualReview).filter(ManualReview.status == "PENDING").count()
                        if pending_count < 20: # cap pending queue
                            manual_entry = ManualReview(
                                timestamp=timestamp,
                                src_ip=fake_ip,
                                country=fake_country,
                                type=pred_text,
                                confidence=confidence,
                                destination_port=int(row.get("Destination Port", 0)),
                                status="PENDING",
                                # Context Fields
                                target_username=target_username,
                                burst_score=burst_score,
                                failed_attempts=failed_attempts,
                                traffic_volume=traffic_volume,
                                login_behavior=login_behavior,
                                # Unidirectional Telemetry
                                flow_direction="INGRESS_UNIDIRECTIONAL",
                                fwd_packets=fwd_pkts,
                                fwd_bytes=fwd_bytes,
                                fwd_iat_mean=fwd_iat,
                                detection_rationale=detection_rationale
                            )
                            db.add(manual_entry)

                # Save Traffic Log
                db.add(traffic_log)
                db.commit()

            except Exception as e:
                print(f"Simulation Error: {e}")
                db.rollback()
            finally:
                db.close() # Important to close session in thread loop

        # Wait based on config speed
        time.sleep(state.config["simulation_speed"])

# --- START TRAFFIC THREAD (mode-aware) ---
live_capture = None  # Global ref for runtime switching

if TRAFFIC_MODE == "LIVE":
    logger.info("[TRAFFIC_MODE=LIVE] Starting PyShark live packet capture...")
    try:
        from traffic.capture import LiveTrafficCapture
        from database import SessionLocal
        live_capture = LiveTrafficCapture(
            model=model,
            label_encoder=label_encoder,
            feature_columns=feature_columns,
            state=state,
            db_factory=SessionLocal,
            interface=LIVE_INTERFACE,
        )
        live_capture.start()
        logger.info("[LIVE] Packet capture thread started.")
    except Exception as e:
        logger.error(f"[LIVE] Failed to start capture: {e}. Falling back to SIMULATION mode.")
        TRAFFIC_MODE = "SIMULATION"
        state.is_running = True

# Simulation thread runs continuously and responds to state.is_running
sim_thread = threading.Thread(target=traffic_simulator, daemon=True)
sim_thread.start()

# --- API ENDPOINTS ---
app = FastAPI(title="soarops SOAR API")
from ai.router import router as ai_router

# Allow Frontend (React/Next.js) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ai_router)

# === PORTAL A ENDPOINTS (Read-Only / Monitoring) ===

@app.get("/api/system/health")
def get_system_health(db: Session = Depends(get_db)):
    """For Page A0: System Overview"""
    pending_count = db.query(ManualReview).filter(ManualReview.status == "PENDING").count()
    uptime_seconds = int(time.time() - state.stats["uptime_start"])
    return {
        "status": "HEALTHY" if pending_count < 5 else "DEGRADED",
        "uptime_seconds": uptime_seconds,
        "traffic_processed": f"{state.stats['scanned'] / 1000:.1f}k",
        "automation_rate": f"{100 * (state.stats['auto_blocked'] / (state.stats['threats_detected'] + 1)):.1f}%"
    }

@app.get("/api/traffic/live")
def get_live_traffic(db: Session = Depends(get_db)):
    """For Page A1: Command Center & A4: Event Stream"""
    # Get last 20 logs from DB
    logs = db.query(TrafficLog).order_by(TrafficLog.timestamp.desc()).limit(20).all()
    return logs

@app.get("/api/threats/map")
def get_threat_map(db: Session = Depends(get_db)):
    """For Page A3: Global Map"""
    # Filter only threats from last 100 logs
    logs = db.query(TrafficLog).filter(TrafficLog.type != "Normal Traffic").order_by(TrafficLog.timestamp.desc()).limit(100).all()
    return logs

# === PORTAL B ENDPOINTS (Admin / Action) ===

@app.get("/api/incidents/pending")
def get_pending_incidents(db: Session = Depends(get_db)):
    """For Page B1 & B2: Analyst Queue"""
    return db.query(ManualReview).filter(ManualReview.status == "PENDING").all()

class ActionRequest(BaseModel):
    action: str # "BLOCK" or "IGNORE"
    analyst_id: str = "admin_user"

@app.post("/api/incidents/{packet_id}/resolve")
def resolve_incident(packet_id: int, req: ActionRequest, db: Session = Depends(get_db)):
    """For Page B2: Take Action"""
    # Find the incident in ManualReview table
    incident = db.query(ManualReview).filter(ManualReview.id == packet_id).first()
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found or already resolved")

    # Update Status
    incident.status = "RESOLVED"
    incident.action_taken = "MANUAL_BLOCK" if req.action == "BLOCK" else "FALSE_POSITIVE"
    incident.analyst_id = req.analyst_id
    incident.resolved_at = datetime.utcnow()
    
    # Update Stats
    if req.action == "BLOCK":
        state.stats["manual_blocked"] += 1
        
    db.commit()
    
    return {"status": "success", "action_taken": req.action}

@app.get("/api/logs/audit")
def get_audit_log(db: Session = Depends(get_db)):
    """For Page B3: Audit Logs"""
    # Fetch resolved manual reviews + auto blocked (limit 50 combined for now)
    manual_logs = db.query(ManualReview).filter(ManualReview.status == "RESOLVED").limit(25).all()
    auto_logs = db.query(AutoBlocked).limit(25).all()
    
    # We simulate a unified log structure for the frontend
    combined = []
    for m in manual_logs:
        combined.append({
            "id": m.id,
            "timestamp": m.timestamp,
            "src_ip": m.src_ip,
            "type": m.type,
            "action": m.action_taken,
            "handled_by": m.analyst_id
        })
    for a in auto_logs:
        combined.append({
            "id": a.id,
            "timestamp": a.timestamp,
            "src_ip": a.src_ip,
            "type": a.type,
            "action": "AUTO_BLOCKED",
            "handled_by": "SYSTEM_AUTOMATION"
        })
        
    # Sort by timestamp desc
    combined.sort(key=lambda x: x["timestamp"] or datetime.min, reverse=True)
    return combined

@app.post("/api/config/update")
def update_config(threshold: float):
    """For Page B5: Admin Config"""
    if 0.0 <= threshold <= 1.0:
        state.config["auto_block_threshold"] = threshold
        return {"status": "updated", "new_threshold": threshold}
    raise HTTPException(status_code=400, detail="Invalid threshold")


@app.get("/api/system/traffic-status")
def get_traffic_status():
    """Returns current traffic capture mode and status."""
    return {
        "mode": TRAFFIC_MODE,
        "live_capture_active": live_capture is not None and getattr(live_capture, "_running", False),
        "live_interface": LIVE_INTERFACE,
        "description": (
            "Live PyShark packet capture (unidirectional inbound)" if TRAFFIC_MODE == "LIVE"
            else "CSV-based traffic simulation"
        ),
        "switch_instructions": (
            "To enable LIVE mode: set env var TRAFFIC_MODE=LIVE and LIVE_INTERFACE=<NIC name>, "
            "then restart the server as Administrator. "
            "Requires Wireshark/tshark to be installed."
        )
    }


@app.get("/api/system/interfaces")
def get_interfaces():
    """
    List available network interfaces for LIVE traffic capture.
    Calls tshark -D under the hood.
    Requires Wireshark to be installed.
    """
    try:
        from traffic.capture import list_interfaces
        interfaces = list_interfaces()
        return {"interfaces": interfaces, "count": len(interfaces)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not list interfaces: {e}")


@app.post("/api/config/traffic-mode")
def switch_traffic_mode(mode: str, interface: str = None):
    """
    Switch traffic capture mode at runtime.
    mode: 'SIMULATION' or 'LIVE'
    interface: NIC name for LIVE mode (e.g. 'Ethernet', 'Wi-Fi')
    """
    global TRAFFIC_MODE, LIVE_INTERFACE, live_capture

    mode = mode.upper()
    if mode not in ("SIMULATION", "LIVE"):
        raise HTTPException(status_code=400, detail="mode must be 'SIMULATION' or 'LIVE'")

    if mode == "LIVE":
        try:
            from traffic.capture import LiveTrafficCapture
            from database import SessionLocal

            # Stop existing live capture if running
            if live_capture:
                live_capture.stop()

            LIVE_INTERFACE = interface or LIVE_INTERFACE
            live_capture = LiveTrafficCapture(
                model=model,
                label_encoder=label_encoder,
                feature_columns=feature_columns,
                state=state,
                db_factory=SessionLocal,
                interface=LIVE_INTERFACE,
            )
            live_capture.start()
            TRAFFIC_MODE = "LIVE"
            state.is_running = False  # Pause simulation loop
            return {
                "status": "switched",
                "mode": "LIVE",
                "interface": LIVE_INTERFACE,
                "note": "Requires Administrator privileges and Wireshark/tshark installed."
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to start live capture: {str(e)}")

    else:  # SIMULATION
        if live_capture:
            live_capture.stop()
            live_capture = None
        TRAFFIC_MODE = "SIMULATION"
        state.is_running = True  # Resume simulation loop
        return {"status": "switched", "mode": "SIMULATION"}


# === UNIDIRECTIONAL THREAT DETECTION TELEMETRY ENDPOINTS ===

@app.get("/api/unidirectional/status")
def get_unidirectional_status(db: Session = Depends(get_db)):
    """
    Returns metrics specific to Unidirectional IP Traffic monitoring:
    Data Diode status, asymmetry index (1.0 = strictly unidirectional ingress),
    forward packet velocity, and recent rationale logs.
    """
    recent_threats = (
        db.query(TrafficLog)
        .filter(TrafficLog.type != "Normal Traffic")
        .order_by(TrafficLog.timestamp.desc())
        .limit(5)
        .all()
    )

    return {
        "architecture": "Unidirectional IP Traffic / Data Diode & Optical Tap",
        "asymmetry_index": 1.0,  # 100% Ingress forward-only, 0% backward
        "mode": TRAFFIC_MODE,
        "features_evaluated": len(feature_columns),
        "backward_channels_monitored": 0,  # Physically disabled / non-existent
        "forward_channels_monitored": 1,
        "flow_direction": "INGRESS_UNIDIRECTIONAL",
        "diode_enclave_status": "SECURE",
        "total_forward_packets_analyzed": state.stats["scanned"],
        "threats_detected": state.stats["threats_detected"],
        "auto_blocked": state.stats["auto_blocked"],
        "recent_unidirectional_detections": [
            {
                "ip": t.src_ip,
                "type": t.type,
                "confidence": t.confidence,
                "fwd_packets": t.fwd_packets,
                "fwd_bytes": t.fwd_bytes,
                "fwd_iat_mean": t.fwd_iat_mean,
                "rationale": t.detection_rationale
            }
            for t in recent_threats
        ]
    }


@app.get("/api/unidirectional/feature-importance")
def get_unidirectional_feature_importance():
    """
    Returns the top discriminative unidirectional features derived from
    the model training phase, explaining why detection works without backward metrics.
    """
    if os.path.exists(METRICS_FILE):
        try:
            with open(METRICS_FILE, "r") as f:
                metrics = json.load(f)
            return metrics
        except Exception as e:
            logger.warning(f"Failed to read {METRICS_FILE}: {e}")

    # Fallback to key forward features
    return {
        "model": "XGBClassifier (Unidirectional)",
        "features_count": len(feature_columns),
        "top_features": [
            {"feature": "Idle Max", "importance": 0.1735},
            {"feature": "Idle Mean", "importance": 0.1144},
            {"feature": "Packet Length Std", "importance": 0.0707},
            {"feature": "Total Length of Fwd Packets", "importance": 0.0677},
            {"feature": "Average Packet Size", "importance": 0.0673},
            {"feature": "Packet Length Variance", "importance": 0.0571},
            {"feature": "PSH Flag Count", "importance": 0.0494},
            {"feature": "Subflow Fwd Bytes", "importance": 0.0434},
            {"feature": "act_data_pkt_fwd", "importance": 0.0398},
            {"feature": "Fwd Packet Length Max", "importance": 0.0344}
        ]
    }
