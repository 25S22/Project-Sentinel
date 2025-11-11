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
import hashlib

# --- MCTS INTEGRATION ---
import mcts_module # Import the new MCTS logic file
# --- END MCTS INTEGRATION ---

# --- CONFIGURATION ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
LOG_FILE_PATH = "sentinel_audit.log"
SURICATA_LOG_PATH = "/var/log/suricata/eve.json"

# --- MODEL CONFIGURATION ---
FLASH_MODEL_NAME = "gemini-1.5-flash"
PRO_MODEL_NAME = "gemini-1.5-pro"
PRO_QUERY_THRESHOLD = 100

# --- ANOMALY DETECTION FILE PATHS ---
ANOMALY_MODEL_PATH = "lstm_autoencoder.keras"
SCALER_PATH = "scaler.gz"
HASHER_PATH = "hasher.gz"
THRESHOLD_PATH = "threshold.txt"

# --- ANOMALY DETECTION PARAMETERS (must match training) ---
TIMESTEPS = 10 
CATEGORICAL_COLS = ['process_name', 'username']
NUMERICAL_COLS = ['cpu_percent', 'memory_percent', 'num_threads'] 
N_HASH_FEATURES = 5
N_FEATURES = N_HASH_FEATURES + len(NUMERICAL_COLS)

# --- ANOMALY DETECTION SENSITIVITY CONTROL ---
ANOMALY_BUFFER_MULTIPLIER = 1.5
MIN_ANOMALY_THRESHOLD = 0.3
ANOMALY_COOLDOWN_SECONDS = 30

# --- Global variables ---
anomaly_model = None
anomaly_scaler = None
anomaly_hasher = None
anomaly_threshold = 0.0
effective_threshold = 0.0
last_anomaly_time = 0
model = None

# --- HELPER FUNCTIONS & API ---
def log_event(data):
    try:
        with open(LOG_FILE_PATH, 'a') as log_file:
            log_entry = {"timestamp": datetime.now().isoformat(), "event_data": data}
            log_file.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        print(f"\nSentinel: [ERROR] Failed to write to log file: {e}")

def get_generative_analysis(prompt, target_model=None):
    active_model = target_model if target_model else model
    if not active_model:
        return "[Analysis Error: Generative model not configured.]"
    try:
        response = active_model.generate_content(prompt)
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
    indicator_type = vt_result.get('type', 'Unknown')
    print(f"Sentinel: OSINT complete. ({indicator_type}) VirusTotal reports {malicious_count} malicious detections.")
    
    print(f"\nSentinel: Performing Quick Search analysis...")

    analysis_prompt = None
    
    if malicious_count > 0:
        analysis_prompt = f"Analyze the indicator '{indicator}' (Type: {indicator_type}).\n\n1. **Overview:** Briefly describe its identity (e.g., website purpose, IP owner).\n\n2. **Threat Analysis:** It was flagged with {malicious_count} malicious detections. Detail the likely threats (phishing, malware, scam, etc.) and risks."
    else:
        analysis_prompt = f"Analyze the indicator '{indicator}' (Type: {indicator_type}).\n\n1. **Overview:** It was found 'clean' by VirusTotal ({malicious_count} detections). Briefly describe its identity (e.g., website purpose, IP owner, 'parked domain').\n\n2. **Security Vetting:** From a security analyst's perspective, are there any *potential* non-malware risks? (e.g., Is it a new domain? Does it have a history of phishing? Does it use excessive trackers? Is it a URL shortener?)"
    
    analysis_text = get_generative_analysis(analysis_prompt)
    
    print("\n--- Sentinel Analysis ---\n" + analysis_text + "\n---------------------------")
    print(f"--- [ END INVESTIGATION ] ---\n")
    return malicious_count, indicator


def check_virustotal_indicator(indicator):
    if not VT_API_KEY:
        return {"indicator": indicator, "status": "error", "message": "VT_API_KEY not configured"}

    try:
        with vt.Client(VT_API_KEY) as client:
            obj_path = ""
            indicator_type = ""
            
            try:
                socket.inet_aton(indicator) # Test if it's a valid IPv4
                obj_path = f"/ip_addresses/{indicator}"
                indicator_type = "IP"
            except socket.error:
                parsed = urlparse(indicator)
                if '://' not in indicator:
                    indicator_url = f"http://{indicator}"
                else:
                    indicator_url = indicator

                if parsed.path and parsed.path != '/':
                    obj_path = f"/urls/{vt.url_id(indicator_url)}"
                    indicator_type = "URL"
                else:
                    domain = parsed.netloc if parsed.netloc else indicator
                    obj_path = f"/domains/{domain}"
                    indicator_type = "Domain"

            result_obj = client.get_object(obj_path)
            stats = result_obj.last_analysis_stats
            return {"indicator": indicator, "type": indicator_type, "status": "completed", "malicious_vendors": stats.get('malicious', 0)}
            
    except Exception as e:
        return {"indicator": indicator, "status": "error", "message": str(e)}

def check_virustotal_hash(file_hash):
    """Checks a file hash (MD5, SHA1, SHA256) against VirusTotal."""
    if not VT_API_KEY:
        return {"hash": file_hash, "status": "error", "message": "VT_API_KEY not configured"}
    try:
        with vt.Client(VT_API_KEY) as client:
            obj_path = f"/files/{file_hash}"
            result_obj = client.get_object(obj_path)
            stats = result_obj.last_analysis_stats
            name = "N/A"
            if hasattr(result_obj, 'meaningful_name'):
                name = result_obj.meaningful_name
            elif hasattr(result_obj, 'names') and result_obj.names:
                name = result_obj.names[0]
                
            return {"hash": file_hash, "status": "completed", "malicious_vendors": stats.get('malicious', 0), "name": name}
    except Exception as e:
        return {"hash": file_hash, "status": "error", "message": str(e)}

def investigate_hash(file_hash, source="MANUAL_INPUT"):
    """Full investigation flow for a file hash."""
    print(f"\n\n--- [ NEW HASH INVESTIGATION ] ---")
    print(f"Source: {source}")
    print(f"Hash: {file_hash}")
    vt_result = check_virustotal_hash(file_hash)
    log_event(vt_result)
    
    if vt_result["status"] == "error":
        print(f"Sentinel: [ERROR] OSINT failed. Reason: {vt_result['message']}")
        return
    
    malicious_count = vt_result['malicious_vendors']
    file_name = vt_result.get('name', 'N/A')
    print(f"Sentinel: OSINT complete. File ({file_name}) has {malicious_count} malicious detections.")
    
    print(f"\nSentinel: Performing Quick Search analysis...")
    
    analysis_prompt = None
    
    if malicious_count > 0:
        analysis_prompt = f"Analyze the file hash '{file_hash}'.\n\n1. **File Name(s):** {file_name}\n\n2. **Threat Analysis:** It was flagged with {malicious_count} malicious detections. Detail the likely malware family (e.g., WannaCry, Emotet), threats (ransomware, trojan, keylogger, etc.), and associated risks."
    else:
        analysis_prompt = f"Analyze the file hash '{file_hash}'.\n\n1. **File Name(s):** {file_name}\n\n2. **Analysis:** It was found 'clean' by VirusTotal ({malicious_count} detections). What is this file? Is it a known-good system file (e.g., part of Windows)? A common library? Or is it an unknown file?"
    
    analysis_text = get_generative_analysis(analysis_prompt)
    
    print("\n--- Sentinel Analysis ---\n" + analysis_text + "\n---------------------------")
    print(f"--- [ END HASH INVESTIGATION ] ---\n")


def block_indicator(indicator, is_permanent=True):
    try:
        is_ip = all(c in "0123456789." for c in indicator)
        ip_to_block = indicator if is_ip else socket.gethostbyname(urlparse(f'//{indicator}' if '://' not in indicator else indicator).hostname)
        
        block_type = "PERMANENT" if is_permanent else "TEMPORARY"
        print(f"Sentinel: Attempting to apply {block_type} firewall block for IP: {ip_to_block}...")
        
        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, "INPUT")
        rule = iptc.Rule()
        rule.src = ip_to_block
        target = iptc.Target(rule, "DROP")
        rule.target = target
        chain.insert_rule(rule)
        table.commit()
        table.refresh()
        
        if verify_rule_exists(ip_to_block):
            msg = f"VERIFICATION SUCCESS: {block_type} firewall rule for {ip_to_block} is active."
            print(f"Sentinel: {msg}")
            log_event({"action": "BLOCK_IP_VERIFIED", "details": msg})
            return True
        else:
            msg = f"VERIFICATION FAILED: {block_type} rule for {ip_to_block} was NOT added."
            print(f"Sentinel: {msg}")
            log_event({"action": "BLOCK_IP_FAILED", "details": msg})
            return False
    except Exception as e:
        if "Name or service not known" in str(e):
            msg = f"Could not resolve domain '{indicator}' to an IP address. No block applied."
            print(f"Sentinel: [ERROR] {msg}")
            log_event({"action": "BLOCK_IP_FAILED", "details": msg})
        else:
            msg = f"An unexpected error occurred during the block action: {e}"
            print(f"Sentinel: [ERROR] {msg}")
            log_event({"action": "BLOCK_IP_EXCEPTION", "details": msg})
        return False

# --- LOGIC UPDATE: Re-added timed unblock functions ---
def unblock_ip(ip_to_unblock):
    """ Helper function to remove a DROP rule for a specific IP. """
    try:
        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, "INPUT")
        
        rules_to_delete = []
        for rule in chain.rules:
            if rule.src and ip_to_unblock in rule.src and rule.target.name == "DROP":
                rules_to_delete.append(rule)
                
        if not rules_to_delete:
            print(f"Sentinel: [UNBLOCK] No active DROP rule found for {ip_to_unblock}.")
            return

        for rule in rules_to_delete:
            chain.delete_rule(rule)
            
        table.commit()
        table.refresh()
        
        msg = f"Temporary block for {ip_to_unblock} has been lifted."
        print(f"Sentinel: {msg}")
        log_event({"action": "UNBLOCK_IP_TEMP", "details": msg})
        
    except Exception as e:
        msg = f"An unexpected error occurred during the unblock action: {e}"
        print(f"Sentinel: [ERROR] {msg}")
        log_event({"action": "UNBLOCK_IP_EXCEPTION", "details": msg})

def apply_temporary_block(ip_address, duration_seconds):
    """
    Applies a temporary block and schedules its removal.
    """
    if block_indicator(ip_address, is_permanent=False):
        # If block was successful, start a timer to remove it
        unblock_timer = threading.Timer(duration_seconds, unblock_ip, args=[ip_address])
        unblock_timer.daemon = True # Ensure timer doesn't block program exit
        unblock_timer.start()
        
        print(f"Sentinel: {ip_address} will be unblocked in {duration_seconds} seconds.")
# --- END LOGIC UPDATE ---


# --- NEW CREATIVE FUNCTION ---
def get_hash_of_file(filepath):
    """Helper to get SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for block in iter(lambda: f.read(4096), b''):
                sha256.update(block)
        return sha256.hexdigest()
    except (IOError, OSError, PermissionError):
        return None

def is_valid_ip(indicator):
    """Helper to check if a string is a valid IP."""
    try:
        socket.inet_aton(indicator)
        return True
    except socket.error:
        return False

def hunt_by_ip(ip_address):
    """Scans active network connections for a specific IP."""
    print(f"Sentinel: [HUNT] Scanning active connections for IP: {ip_address}...")
    found_procs = []
    try:
        for conn in psutil.net_connections():
            if conn.raddr and conn.raddr.ip == ip_address and conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    proc_info = {
                        'pid': conn.pid,
                        'name': proc.name(),
                        'user': proc.username(),
                        'status': conn.status
                    }
                    if proc_info not in found_procs:
                        found_procs.append(proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        if not found_procs:
            print(f"Sentinel: [HUNT] No active processes found communicating with {ip_address}.")
        else:
            print(f"Sentinel: [HUNT] 🚨 THREAT FOUND! Active processes communicating with {ip_address}:")
            for proc in found_procs:
                print(f"  - PID: {proc['pid']}, Name: {proc['name']}, User: {proc['user']}, Status: {proc['status']}")
            
    except Exception as e:
        print(f"Sentinel: [ERROR] An error occurred during IP hunt: {e}")

def hunt_by_hash(target_hash):
    """Scans running processes by their executable hash."""
    print(f"Sentinel: [HUNT] Scanning running processes for hash: {target_hash}...")
    found_procs = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                exe_path = proc.info['exe']
                if exe_path and os.path.exists(exe_path):
                    file_hash = get_hash_of_file(exe_path)
                    if file_hash == target_hash:
                        proc_info = {
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'path': exe_path
                        }
                        if proc_info not in found_procs:
                            found_procs.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
                continue
                
        if not found_procs:
            print(f"Sentinel: [HUNT] No running processes found matching hash {target_hash}.")
        else:
            print(f"Sentinel: [HUNT] 🚨 THREAT FOUND! Running processes matching hash {target_hash}:")
            for proc in found_procs:
                print(f"  - PID: {proc['pid']}, Name: {proc['name']}, Path: {proc['path']}")
                
    except Exception as e:
        print(f"Sentinel: [ERROR] An error occurred during hash hunt: {e}")

def hunt_threat(indicator):
    """Main threat hunting function."""
    print(f"\n--- [ NEW THREAT HUNT ] ---")
    print(f"Indicator: {indicator}")
    
    # 1. Check if it's an IP
    if is_valid_ip(indicator):
        hunt_by_ip(indicator)
        return

    # 2. Check if it's a hash (MD5, SHA1, SHA256)
    hash_len = len(indicator)
    if hash_len == 32 or hash_len == 40 or hash_len == 64:
        print("Sentinel: [HUNT] Detected indicator as a file hash.")
        hunt_by_hash(indicator.lower())
        return
        
    # 3. Try to resolve as a domain
    print(f"Sentinel: [HUNT] Indicator is not a valid IP or hash. Attempting to resolve as a domain...")
    try:
        ip_address = socket.gethostbyname(indicator)
        print(f"Sentinel: [HUNT] Domain {indicator} resolved to {ip_address}.")
        hunt_by_ip(ip_address)
    except socket.error:
        print(f"Sentinel: [HUNT] Could not resolve domain {indicator}. Hunt aborted.")
# --- END NEW CREATIVE FUNCTION ---


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
                            dest_ip = alert.get('dest_ip')
                            signature = alert.get('alert', {}).get('signature')
                            severity = alert.get('alert', {}).get('severity')
                            
                            print(f"\nSentinel: [SURICATA ALERT] Severity: {severity} | {signature} | From: {src_ip} -> To: {dest_ip}")
                            
                            if severity <= 2: # 1=High, 2=Medium
                                print(f"Sentinel: [MCTS TRIGGER] High severity network threat detected. Initiating MCTS.")
                                
                                initial_state = {
                                    'type': 'network_threat',
                                    'attacker_ip': src_ip,
                                    'target_host': dest_ip,
                                    'signature': signature,
                                    'severity': severity
                                }
                                
                                # MCTS runs *fast* to get a recommendation (e.g., "block_ip_temp")
                                best_move, predicted_moves = mcts_module.get_best_defensive_action(initial_state)
                                
                                # --- LOGIC UPDATE: Intelligent action block ---
                                print("\n" + "="*50)
                                if "block_ip" in best_move:
                                    print(f"Sentinel: MCTS recommends block for {src_ip}. Cross-checking reputation...")
                                    vt_result = check_virustotal_indicator(src_ip)
                                    malicious_count = vt_result.get('malicious_vendors', 0)
                                    
                                    if malicious_count > 0:
                                        print(f"Sentinel: [!] Reputation is MALICIOUS ({malicious_count} vendors). Escalating to PERMANENT block.")
                                        block_indicator(src_ip, is_permanent=True)
                                        print(f"🛡️  ACTION EXECUTED: Permanently blocking {src_ip}.")
                                    else:
                                        print(f"Sentinel: Reputation is CLEAN. Applying TEMPORARY 10-second block as recommended.")
                                        apply_temporary_block(src_ip, 10) # This function now handles the timer
                                        print(f"🛡️  ACTION RESTRICTED: Activity from {src_ip} is restricted for the next 10 seconds.")
                                
                                else:
                                    # Handle other non-block actions from MCTS
                                    print(f"🛡️  ACTION RECOMMENDED: {best_move}. (No automated execution configured for this action).")
                                print("="*50)
                                # --- END LOGIC UPDATE ---
                                
                                log_event({
                                    "action": "MCTS_RESPONSE_NETWORK",
                                    "state": initial_state,
                                    "best_move": best_move,
                                    "predicted_attacker_moves": predicted_moves
                                })
                                
                            else:
                                print(f"Sentinel: Low severity alert. Performing standard investigation...")
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
    global anomaly_model, anomaly_scaler, anomaly_hasher, anomaly_threshold, effective_threshold, last_anomaly_time
    
    if not all([anomaly_model, anomaly_scaler, anomaly_hasher]):
        print("Sentinel: [ANOMALY MONITOR ERROR] Anomaly detection components not fully loaded. Monitor disabled.")
        return

    print(f"Sentinel: Advanced anomaly monitoring thread started. Using effective threshold: {effective_threshold:.4f}")
    recent_features = []
    consecutive_anomalies = 0
    last_anomalous_df = pd.DataFrame() 
    
    while True:
        try:
            procs_info = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'num_threads']):
                try:
                    proc_data = proc.info
                    if all(key in proc_data and proc_data[key] is not None for key in ['name', 'username', 'cpu_percent', 'memory_percent', 'num_threads']):
                        processed_data = {
                            'pid': int(proc_data['pid']),
                            'process_name': str(proc_data['name'] if proc_data['name'] else 'unknown'),
                            'username': str(proc_data['username'] if proc_data['username'] else 'unknown'),
                            'cpu_percent': float(proc_data['cpu_percent'] if proc_data['cpu_percent'] is not None else 0.0),
                            'memory_percent': round(float(proc_data['memory_percent'] if proc_data['memory_percent'] is not None else 0.0), 2),
                            'num_threads': int(proc_data['num_threads'] if proc_data['num_threads'] is not None else 1)
                        }
                        procs_info.append(processed_data)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, ValueError, TypeError):
                    continue

            if not procs_info:
                time.sleep(5)
                continue

            live_df = pd.DataFrame(procs_info)
            live_df = live_df.dropna()
            if live_df.empty:
                time.sleep(5)
                continue

            try:
                model_df = live_df.copy()
                categorical_live = model_df[CATEGORICAL_COLS].astype(str).to_dict('records')
                numerical_live = model_df[NUMERICAL_COLS].values
                
                if numerical_live.shape[1] != len(NUMERICAL_COLS):
                    continue
                
                hashed_live = anomaly_hasher.transform(categorical_live)
                
                if numerical_live.shape[1] != anomaly_scaler.n_features_in_:
                    continue
                
                scaled_live = anomaly_scaler.transform(numerical_live)
                combined_live_features = np.hstack((hashed_live.toarray(), scaled_live))

                recent_features.extend(combined_live_features)
                
                while len(recent_features) > TIMESTEPS:
                    recent_features.pop(0)

                if len(recent_features) == TIMESTEPS:
                    sequence_np = np.array(recent_features).reshape(1, TIMESTEPS, N_FEATURES)
                    reconstruction = anomaly_model.predict(sequence_np, verbose=0)
                    mae_loss = np.mean(np.abs(reconstruction - sequence_np))

                    current_time = time.time()
                    is_significant_anomaly = mae_loss > effective_threshold
                    cooldown_passed = (current_time - last_anomaly_time) > ANOMALY_COOLDOWN_SECONDS

                    if is_significant_anomaly:
                        consecutive_anomalies += 1
                        last_anomalous_df = live_df.copy()
                        
                        should_alert = cooldown_passed and (consecutive_anomalies == 1 or consecutive_anomalies >= 3)
                        
                        if should_alert:
                            severity = "HIGH" if mae_loss > (effective_threshold * 2) else "MEDIUM"
                            print(f"\nSentinel: [ANOMALY DETECTED - {severity}] Reconstruction Error: {mae_loss:.4f} > Threshold: {effective_threshold:.4f}")
                            print(f"Sentinel: Base threshold was {anomaly_threshold:.4f}, using buffered threshold {effective_threshold:.4f}")
                            
                            last_anomaly_time = current_time
                            
                            # MCTS runs FIRST
                            print(f"Sentinel: [MCTS TRIGGER] High severity host anomaly detected. Initiating MCTS.")
                            
                            suspicious_proc_name = "unknown"
                            suspicious_pid = 0
                            if not last_anomalous_df.empty:
                                last_anomalous_df['anomaly_score'] = last_anomalous_df['cpu_percent'] + last_anomalous_df['memory_percent']
                                most_suspicious = last_anomalous_df.loc[last_anomalous_df['anomaly_score'].idxmax()]
                                suspicious_proc_name = most_suspicious['process_name']
                                suspicious_pid = int(most_suspicious['pid'])
                                print(f"Sentinel: [MCTS] Identified most anomalous process: {suspicious_proc_name} (PID: {suspicious_pid})")

                            initial_state = {
                                'type': 'host_anomaly',
                                'severity': severity,
                                'suspicious_process': suspicious_proc_name,
                                'suspicious_pid': suspicious_pid,
                                'loss_score': mae_loss
                            }
                            
                            best_move, predicted_moves = mcts_module.get_best_defensive_action(initial_state)
                            
                            print("\n" + "="*50)
                            if "kill_process" in best_move and suspicious_pid != 0:
                                print(f"🛡️  ACTION EXECUTED: Killing process tree for {suspicious_proc_name} (PID: {suspicious_pid}) to prevent APT.")
                                try:
                                    proc = psutil.Process(suspicious_pid)
                                    for child in proc.children(recursive=True):
                                        child.kill()
                                    proc.kill()
                                    print(f"Sentinel: Process {suspicious_proc_name} (PID: {suspicious_pid}) and children terminated.")
                                except Exception as e:
                                    print(f"Sentinel: [ERROR] Failed to kill process: {e}")
                            else:
                                print(f"🛡️  ACTION RESTRICTED: Activity {best_move} is restricted for the next 10 seconds to prevent APT from moving to next steps!")
                            print("="*50)

                            log_event({
                                "action": "MCTS_RESPONSE_HOST",
                                "state": initial_state,
                                "best_move": best_move,
                                "predicted_attacker_moves": predicted_moves
                            })
                            
                            # Generative analysis runs AFTER
                            print(f"Sentinel: Performing follow-up analysis on anomaly...")
                            prompt = f"Investigate a {severity.lower()} security anomaly. System behavior deviated significantly from the norm (reconstruction error: {mae_loss:.4f} vs threshold: {effective_threshold:.4f}). This indicates unusual patterns across multiple system processes. Analyze potential threats like malware, rootkits, or resource abuse and suggest immediate response steps for a sysadmin."
                            
                            analysis = get_generative_analysis(prompt)
                            print("\n--- Anomaly Analysis ---\n" + analysis + "\n-----------------------------------")
                            
                            log_event({"action": "ANOMALY_DETECTED", "loss": mae_loss, "effective_threshold": effective_threshold, "severity": severity, "details": analysis})
                            
                        else:
                            print(f"Sentinel: [DEBUG] Minor anomaly detected ({mae_loss:.4f}) - cooldown active or low consecutive count ({consecutive_anomalies})")
                    else:
                        if consecutive_anomalies > 0:
                            print(f"Sentinel: [INFO] System behavior normalized (error: {mae_loss:.4f})")
                        consecutive_anomalies = 0
                        
                    recent_features.pop(0)

            except Exception as e:
                print(f"Sentinel: [ANOMALY MONITOR ERROR] Data processing error: {e}")
                continue

            time.sleep(2)
        except Exception as e:
            print(f"Sentinel: [ANOMALY MONITOR ERROR] An unexpected error occurred: {e}")
            time.sleep(5)

# --- MAIN APPLICATION & CLI THREAD ---
def run_sentinel_cli():
    print("\nSentinel: Greetings, I am your personal defensive agent. How can I assist you?")
    while True:
        try:
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
                        block_indicator(indicator, is_permanent=True) # This is permanent, as requested
                    else:
                        print("Sentinel: Understood. No action will be taken.")
                        log_event({"action": "USER_DECLINED_BLOCK", "indicator": indicator})
            
            elif user_input.lower().startswith("check_hash"):
                parts = user_input.split()
                if len(parts) < 2:
                    print("Sentinel: Please provide a file hash. Usage: check_hash <hash>")
                    continue
                hash_to_check = parts[1]
                investigate_hash(hash_to_check)
            
            elif user_input.lower().startswith("hunt_threat"):
                parts = user_input.split()
                if len(parts) < 2:
                    print("Sentinel: Please provide an indicator. Usage: hunt_threat <ip|domain|hash>")
                    continue
                indicator_to_hunt = parts[1]
                hunt_threat(indicator_to_hunt)
            
            else:
                query_length = len(user_input)
                
                if query_length > PRO_QUERY_THRESHOLD:
                    print(f"Sentinel: Processing complex query (length {query_length}) with Deep Search...")
                    try:
                        pro_model_instance = genai.GenerativeModel(PRO_MODEL_NAME)
                        response = pro_model_instance.generate_content(user_input)
                        print(f"Sentinel: {response.text}")
                    except Exception as e:
                        print(f"Sentinel: [Analysis Error: Could not process Deep Search request. Reason: {e}]")
                else:
                    print(f"Sentinel: Processing fast query (length {query_length}) with Quick Search...")
                    response_text = get_generative_analysis(user_input, target_model=model)
                    print(f"Sentinel: {response_text}")
                
        except KeyboardInterrupt:
            print("\nSentinel: Shutting down.")
            os._exit(0)
        except Exception as e:
            print(f"Sentinel: [CLI ERROR] An error occurred: {e}")
            continue

if __name__ == "__main__":
    try:
        print("Sentinel: Loading anomaly detection model and preprocessors...")
        anomaly_model = tf.keras.models.load_model(ANOMALY_MODEL_PATH, compile=False)
        anomaly_scaler = joblib.load(SCALER_PATH) # Fixed typo
        anomaly_hasher = joblib.load(HASHER_PATH)
        with open(THRESHOLD_PATH, 'r') as f:
            anomaly_threshold = float(f.read().strip())
        
        expected_features = anomaly_scaler.n_features_in_
        if expected_features != len(NUMERICAL_COLS):
            print(f"Sentinel: [WARNING] Scaler expects {expected_features} features, but NUMERICAL_COLS has {len(NUMERICAL_COLS)}. This may cause errors.")
        
        base_threshold = anomaly_threshold
        buffered_threshold = base_threshold * ANOMALY_BUFFER_MULTIPLIER
        effective_threshold = max(buffered_threshold, MIN_ANOMALY_THRESHOLD)
        
        print(f"Sentinel: Threshold Configuration:")
        print(f"  - Base threshold (from training): {base_threshold:.4f}")
        print(f"  - Buffered threshold (x{ANOMALY_BUFFER_MULTIPLIER}): {buffered_threshold:.4f}")
        print(f"  - Effective threshold (final): {effective_threshold:.4f}")
        print(f"  - Minimum threshold: {MIN_ANOMALY_THRESHOLD}")
        
        if GEMINI_API_KEY and VT_API_KEY:
            genai.configure(api_key=GEMINI_API_KEY)
            model = genai.GenerativeModel(FLASH_MODEL_NAME)
            print(f"Sentinel: Online analysis tools configured.")
            print(f"  - Default (Quick Search) model: {FLASH_MODEL_NAME}")
            print(f"  - On-demand (Deep Search) model: {PRO_MODEL_NAME}")
        else:
            print("Sentinel: [WARNING] API keys not found. OSINT and analysis will be disabled.")

        print(f"Sentinel: Advanced model and preprocessors loaded. Effective threshold set to {effective_threshold:.4f}.")
    except Exception as e:
        print(f"Sentinel: [ERROR] Failed to load components: {e}. Anomaly detection will be disabled.")
        anomaly_model = None

    suricata_thread = threading.Thread(target=run_suricata_monitor, daemon=True)
    suricata_thread.start()
    if anomaly_model:
        anomaly_thread = threading.Thread(target=run_anomaly_monitor, daemon=True)
        anomaly_thread.start()

    run_sentinel_cli()
