import google.generativeai as genai
import os
import sys
import socket
import iptc
import vt
import json
import time
import threading
from datetime import datetime
from urllib.parse import urlparse
import numpy as np
import pandas as pd
import tensorflow as tf
import psutil # Used for live data collection
import joblib

# --- CONFIGURATION ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
LOG_FILE_PATH = "sentinel_audit.log"
SURICATA_LOG_PATH = "/var/log/suricata/eve.json"

# --- ANOMALY DETECTION FILE PATHS ---
ANOMALY_MODEL_PATH = "lstm_autoencoder.keras"
SCALER_PATH = "scaler.gz"
HASHER_PATH = "hasher.gz"
THRESHOLD_PATH = "threshold.txt"

# --- ANOMALY DETECTION PARAMETERS (must match training) ---
TIMESTEPS = 10 
CATEGORICAL_COLS = ['process_name', 'username']
# 'net_connections' has been removed
NUMERICAL_COLS = ['cpu_percent', 'memory_percent', 'num_threads'] 
N_HASH_FEATURES = 5
N_FEATURES = N_HASH_FEATURES + len(NUMERICAL_COLS)

# --- Global variables for the anomaly detection components ---
anomaly_model = None
anomaly_scaler = None
anomaly_hasher = None
anomaly_threshold = 0.0
model = None # Gemini model

# --- HELPER FUNCTIONS & API ---
def log_event(data):
    try:
        with open(LOG_FILE_PATH, 'a') as log_file:
            log_entry = {"timestamp": datetime.now().isoformat(), "event_data": data}
            log_file.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        print(f"\nSentinel: [ERROR] Failed to write to log file: {e}")

def get_generative_analysis(prompt):
    if not model:
        return "[Analysis Error: Generative model not configured.]"
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"[Analysis Error: Could not process request. Reason: {e}]"

def verify_rule_exists(ip_to_check):
    try:
        table = iptc.Table(iptc.Table.FILTER)
        table.refresh()
        chain = iptc.Chain(table, "INPUT")
        for rule in chain.rules:
            if rule.src and ip_to_check in rule.src:
                return True
        return False
    except Exception as e:
        print(f"\nSentinel: [VERIFICATION ERROR] Could not read iptables rules: {e}")
        return False

# --- ANALYSIS & BLOCKING LOGIC ---
def investigate_indicator(indicator, source="MANUAL_INPUT"):
    print(f"\n\n--- [ NEW INVESTIGATION ] ---")
    print(f"Source: {source}")
    print(f"Indicator: {indicator}")
    vt_result = check_virustotal_indicator(indicator)
    log_event(vt_result)
    if vt_result["status"] == "error":
        print(f"Sentinel: [ERROR] OSINT failed. Reason: {vt_result['message']}")
        return None, None
    malicious_count = vt_result['malicious_vendors']
    print(f"Sentinel: OSINT complete. VirusTotal reports {malicious_count} malicious detections.")
    print(f"\nSentinel: Performing generative analysis...")
    if malicious_count > 0:
        analysis_prompt = f"Analyze the indicator '{indicator}'.\n\n1. **Overview:** Briefly describe its identity (e.g., website purpose, IP owner).\n\n2. **Threat Analysis:** It was flagged with {malicious_count} malicious detections. Detail the likely threats (phishing, malware, scam, etc.) and risks."
    else:
        analysis_prompt = f"Analyze the indicator '{indicator}'.\n\n1. **Detailed Overview:** Provide a detailed overview of the website or IP owner.\n\n2. **Security Reputation:** Conclude with its security reputation, noting it was not flagged by scanners."
    analysis_text = get_generative_analysis(analysis_prompt)
    print("\n--- Generative Analysis ---\n" + analysis_text + "\n---------------------------")
    print(f"--- [ END INVESTIGATION ] ---\n")
    return malicious_count, indicator

def check_virustotal_indicator(indicator):
    if not VT_API_KEY:
        return {"indicator": indicator, "status": "error", "message": "VT_API_KEY not configured"}
    is_ip = all(c in "0123456789." for c in indicator)
    try:
        with vt.Client(VT_API_KEY) as client:
            obj_path = f"/ip_addresses/{indicator}" if is_ip else f"/urls/{vt.url_id(indicator)}"
            result_obj = client.get_object(obj_path)
            stats = result_obj.last_analysis_stats
            return {"indicator": indicator, "status": "completed", "malicious_vendors": stats.get('malicious', 0)}
    except Exception as e:
        return {"indicator": indicator, "status": "error", "message": str(e)}

def block_indicator(indicator):
    try:
        is_ip = all(c in "0123456789." for c in indicator)
        ip_to_block = indicator if is_ip else socket.gethostbyname(urlparse(f'//{indicator}' if '://' not in indicator else indicator).hostname)
        print(f"Sentinel: Attempting to apply firewall block for IP: {ip_to_block}...")
        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, "INPUT")
        rule = iptc.Rule()
        rule.src = ip_to_block
        rule.target = chain.create_target("DROP")
        chain.insert_rule(rule)
        table.commit()
        table.refresh()
        if verify_rule_exists(ip_to_block):
            msg = f"VERIFICATION SUCCESS: Firewall rule for {ip_to_block} is active."
            print(f"Sentinel: {msg}")
            log_event({"action": "BLOCK_IP_VERIFIED", "details": msg})
        else:
            msg = f"VERIFICATION FAILED: Rule for {ip_to_block} was NOT added."
            print(f"Sentinel: {msg}")
            log_event({"action": "BLOCK_IP_FAILED", "details": msg})
    except Exception as e:
        msg = f"An unexpected error occurred during the block action: {e}"
        print(f"Sentinel: [ERROR] {msg}")
        log_event({"action": "BLOCK_IP_EXCEPTION", "details": msg})

# --- SURICATA MONITOR THREAD ---
def run_suricata_monitor():
    print("Sentinel: Suricata monitoring thread started. Watching logs...")
    try:
        with open(SURICATA_LOG_PATH, 'r') as log_file:
            log_file.seek(0, 2)
            while True:
                new_line = log_file.readline()
                if new_line:
                    try:
                        alert = json.loads(new_line)
                        if alert.get('event_type') == 'alert':
                            src_ip = alert.get('src_ip')
                            signature = alert.get('alert', {}).get('signature')
                            print(f"\nSentinel: [SURICATA ALERT] Detected: {signature} from {src_ip}")
                            investigate_indicator(src_ip, source=f"SURICATA: {signature}")
                    except json.JSONDecodeError:
                        continue
                else:
                    time.sleep(1)
    except FileNotFoundError:
        print(f"Sentinel: [MONITOR ERROR] Suricata log not found at {SURICATA_LOG_PATH}. Suricata monitor is disabled.")
    except Exception as e:
        print(f"Sentinel: [MONITOR ERROR] An unexpected error occurred in Suricata monitor: {e}")

# --- ADVANCED ANOMALY MONITOR THREAD ---
def run_anomaly_monitor():
    global anomaly_model, anomaly_scaler, anomaly_hasher, anomaly_threshold
    if not all([anomaly_model, anomaly_scaler, anomaly_hasher]):
        print("Sentinel: [ANOMALY MONITOR ERROR] Anomaly detection components not fully loaded. Monitor disabled.")
        return

    print("Sentinel: Advanced anomaly monitoring thread started. Watching live system state...")
    recent_features = []
    while True:
        try:
            # Get a snapshot of all running processes' data
            # 'connections' is removed from the attributes list
            procs_info = [p.info for p in psutil.process_iter(['name', 'username', 'cpu_percent', 'memory_percent', 'num_threads'])]
            
            live_df = pd.DataFrame(procs_info).dropna()

            if live_df.empty:
                time.sleep(2)
                continue

            # Preprocess the live data snapshot
            categorical_live = live_df[CATEGORICAL_COLS].astype(str).to_dict('records')
            numerical_live = live_df[NUMERICAL_COLS].values
            
            hashed_live = anomaly_hasher.transform(categorical_live)
            scaled_live = anomaly_scaler.transform(numerical_live)
            
            combined_live_features = np.hstack((hashed_live.toarray(), scaled_live))

            # Add the current state to our sequence buffer
            recent_features.extend(combined_live_features)
            
            # Trim the buffer to maintain the sequence length
            while len(recent_features) > TIMESTEPS:
                recent_features.pop(0)

            # Check for anomaly if we have a full sequence
            if len(recent_features) == TIMESTEPS:
                sequence_np = np.array(recent_features).reshape(1, TIMESTEPS, N_FEATURES)
                reconstruction = anomaly_model.predict(sequence_np, verbose=0)
                mae_loss = np.mean(np.abs(reconstruction - sequence_np))

                if mae_loss > anomaly_threshold:
                    print(f"\nSentinel: [ANOMALY DETECTED] Reconstruction Error: {mae_loss:.4f} > Threshold: {anomaly_threshold:.4f}")
                    prompt = f"Investigate a major security anomaly. System behavior deviated significantly from the norm (reconstruction error: {mae_loss:.4f}). This indicates a coordinated, unusual pattern across multiple system processes. Analyze potential threats like malware, rootkits, or resource abuse and suggest immediate response steps for a sysadmin."
                    analysis = get_generative_analysis(prompt)
                    print("\n--- Anomaly Generative Analysis ---\n" + analysis + "\n-----------------------------------")
                    log_event({"action": "ANOMALY_DETECTED", "loss": mae_loss, "details": analysis})
                    recent_features = [] # Reset after detection

            time.sleep(2)
        except Exception as e:
            print(f"Sentinel: [ANOMALY MONITOR ERROR] An unexpected error occurred: {e}")
            time.sleep(5)

# --- MAIN APPLICATION & CLI THREAD ---
def run_sentinel_cli():
    print("\nSentinel: Greetings, I am your personal defensive agent. How can I assist you?")
    while True:
        user_input = input("You > ")
        if user_input.lower() in ['exit', 'quit']:
            print("Sentinel: Shutting down.")
            os._exit(0)
        if user_input.lower().startswith("check_reputation"):
            parts = user_input.split()
            if len(parts) < 2:
                print("Sentinel: Please provide a URL or IP. Usage: check_reputation <indicator>")
                continue
            indicator_to_check = parts[1]
            malicious_count, indicator = investigate_indicator(indicator_to_check)
            if malicious_count is not None and malicious_count > 0:
                confirmation = input("\nSentinel: Threat detected. Would you like to block this indicator? (yes/no) > ")
                if confirmation.lower() == 'yes':
                    block_indicator(indicator)
                else:
                    print("Sentinel: Understood. No action will be taken.")
                    log_event({"action": "USER_DECLINED_BLOCK", "indicator": indicator})
        else:
            print("Sentinel: Processing general query...")
            response_text = get_generative_analysis(user_input)
            print(f"Sentinel: {response_text}")

if __name__ == "__main__":
    try:
        print("Sentinel: Loading anomaly detection model and preprocessors...")
        anomaly_model = tf.keras.models.load_model(ANOMALY_MODEL_PATH, compile=False)
        anomaly_scaler = joblib.load(SCALER_PATH)
        anomaly_hasher = joblib.load(HASHER_PATH)
        with open(THRESHOLD_PATH, 'r') as f:
            anomaly_threshold = float(f.read().strip())
        
        if GEMINI_API_KEY and VT_API_KEY:
            genai.configure(api_key=GEMINI_API_KEY)
            model = genai.GenerativeModel('gemini-1.5-flash')
            print("Sentinel: Online analysis tools (Gemini, VirusTotal) are configured.")
        else:
            print("Sentinel: [WARNING] API keys not found. OSINT and generative analysis will be disabled.")

        print(f"Sentinel: Advanced model and preprocessors loaded. Threshold set to {anomaly_threshold:.4f}.")
    except Exception as e:
        print(f"Sentinel: [ERROR] Failed to load components: {e}. Anomaly detection will be disabled.")
        anomaly_model = None

    suricata_thread = threading.Thread(target=run_suricata_monitor, daemon=True)
    suricata_thread.start()
    if anomaly_model:
        anomaly_thread = threading.Thread(target=run_anomaly_monitor, daemon=True)
        anomaly_thread.start()

    run_sentinel_cli()
