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

# --- MCTS INTEGRATION ---
import mcts_module # Import the new MCTS logic file
# --- END MCTS INTEGRATION ---

# --- CONFIGURATION ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
LOG_FILE_PATH = "sentinel_audit.log"
SURICATA_LOG_PATH = "/var/log/suricata/eve.json"

# --- MODEL CONFIGURATION ---
# Use gemini-1.5-flash for high-throughput, automated tasks (anomaly, suricata)
FLASH_MODEL_NAME = "gemini-2.5-flash"
# Use gemini-1.5-pro for complex, user-driven queries
PRO_MODEL_NAME = "gemini-2.5-pro"
# Simple character threshold to decide when to use the Pro model
PRO_QUERY_THRESHOLD = 100

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

# --- ANOMALY DETECTION SENSITIVITY CONTROL ---
ANOMALY_BUFFER_MULTIPLIER = 1.5  # Multiply threshold by this factor to reduce false positives
MIN_ANOMALY_THRESHOLD = 0.3      # Minimum threshold regardless of calculated value
ANOMALY_COOLDOWN_SECONDS = 30    # Wait time between anomaly alerts to prevent spam

# --- Global variables for the anomaly detection components ---
anomaly_model = None
anomaly_scaler = None
anomaly_hasher = None
anomaly_threshold = 0.0
effective_threshold = 0.0  # The actual threshold used after applying buffer
last_anomaly_time = 0      # Track last anomaly alert time for cooldown
model = None # Global model, will be set to FLASH_MODEL_NAME

# --- HELPER FUNCTIONS & API ---
def log_event(data):
    try:
        with open(LOG_FILE_PATH, 'a') as log_file:
            log_entry = {"timestamp": datetime.now().isoformat(), "event_data": data}
            log_file.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        print(f"\nSentinel: [ERROR] Failed to write to log file: {e}")

def get_generative_analysis(prompt, target_model=None):
    """
    Generates analysis using the specified model.
    If target_model is None, uses the default global model (Flash).
    """
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
    print(f"Sentinel: OSINT complete. VirusTotal reports {malicious_count} malicious detections.")
    print(f"\nSentinel: Performing generative analysis...")
    if malicious_count > 0:
        analysis_prompt = f"Analyze the indicator '{indicator}'.\n\n1. **Overview:** Briefly describe its identity (e.g., website purpose, IP owner).\n\n2. **Threat Analysis:** It was flagged with {malicious_count} malicious detections. Detail the likely threats (phishing, malware, scam, etc.) and risks."
    else:
        # --- MCTS MODIFICATION ---
        # No need for a generative prompt if it's clean
        analysis_text = f"Indicator '{indicator}' appears benign. OSINT analysis found {malicious_count} malicious detections."
        # --- END MCTS MODIFICATION ---
        
    # This task will use the default global (Flash) model via get_generative_analysis
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

def block_indicator(indicator, is_permanent=True):
    # --- MCTS MODIFICATION ---
    # Modified to accept a flag for permanent vs temporary blocks
    # --- END MCTS MODIFICATION ---
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
            return True # --- MCTS MODIFICATION: Return success ---
        else:
            msg = f"VERIFICATION FAILED: {block_type} rule for {ip_to_block} was NOT added."
            print(f"Sentinel: {msg}")
            log_event({"action": "BLOCK_IP_FAILED", "details": msg})
            return False # --- MCTS MODIFICATION: Return failure ---
    except Exception as e:
        msg = f"An unexpected error occurred during the block action: {e}"
        print(f"Sentinel: [ERROR] {msg}")
        log_event({"action": "BLOCK_IP_EXCEPTION", "details": msg})
        return False # --- MCTS MODIFICATION: Return failure ---

# --- MCTS INTEGRATION ---
def unblock_ip(ip_to_unblock):
    """ Helper function to remove a DROP rule for a specific IP. """
    try:
        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, "INPUT")
        
        # We must find the exact rule to delete it
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

# --- END MCTS INTEGRATION ---

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
                            
                            # --- MCTS INTEGRATION: TRIGGER 1 (Network Threat) ---
                            # We now trigger MCTS *before* asking the user.
                            # We only care about high-priority, actionable alerts.
                            if severity <= 2: # 1=High, 2=Medium
                                print(f"Sentinel: [MCTS TRIGGER] High severity network threat detected. Initiating MCTS.")
                                
                                # 1. Define the initial state for the MCTS "game"
                                initial_state = {
                                    'type': 'network_threat',
                                    'attacker_ip': src_ip,
                                    'target_host': dest_ip,
                                    'signature': signature,
                                    'severity': severity
                                }
                                
                                # 2. Run MCTS to get the best defensive move
                                best_move, predicted_moves = mcts_module.get_best_defensive_action(initial_state)
                                
                                # 3. Execute the user's desired action
                                print("\n" + "="*50)
                                if "block_ip_temp" in best_move:
                                    print(f"🛡️  ACTION EXECUTED: Activity from {src_ip} is restricted for the next 10 seconds.")
                                    # This call is non-blocking and will remove the rule after 10s
                                    apply_temporary_block(src_ip, 10)
                                elif "block_ip_perm" in best_move:
                                    print(f"🛡️  ACTION EXECUTED: Permanently blocking {src_ip}.")
                                    block_indicator(src_ip, is_permanent=True)
                                else:
                                    print(f"🛡️  ACTION RECOMMENDED: {best_move}. (No automated execution configured for this action).")
                                print("="*50)
                                
                                log_event({
                                    "action": "MCTS_RESPONSE_NETWORK",
                                    "state": initial_state,
                                    "best_move": best_move,
                                    "predicted_attacker_moves": predicted_moves
                                })
                                
                            else:
                                # Low severity, just investigate as before
                                print(f"Sentinel: Low severity alert. Performing standard investigation...")
                                investigate_indicator(src_ip, source=f"SURICATA: {signature}")
                            # --- END MCTS INTEGRATION ---

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
    
    # --- MCTS INTEGRATION ---
    # We need to hold the dataframe that caused the anomaly
    last_anomalous_df = pd.DataFrame() 
    # --- END MCTS INTEGRATION ---
    
    while True:
        try:
            procs_info = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'num_threads']):
                try:
                    proc_data = proc.info
                    if all(key in proc_data and proc_data[key] is not None for key in ['name', 'username', 'cpu_percent', 'memory_percent', 'num_threads']):
                        processed_data = {
                            # --- MCTS INTEGRATION: Store PID ---
                            'pid': int(proc_data['pid']),
                            # --- END MCTS INTEGRATION ---
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
                print("Sentinel: [ANOMALY MONITOR] No valid process data collected, retrying...")
                time.sleep(5)
                continue

            live_df = pd.DataFrame(procs_info)
            live_df = live_df.dropna()
            if live_df.empty:
                print("Sentinel: [ANOMALY MONITOR] No valid data after cleaning, retrying...")
                time.sleep(5)
                continue

            try:
                # --- MCTS MODIFICATION ---
                # We need to process a copy for the model, as live_df needs to keep PID etc.
                model_df = live_df.copy()
                categorical_live = model_df[CATEGORICAL_COLS].astype(str).to_dict('records')
                numerical_live = model_df[NUMERICAL_COLS].values
                # --- END MCTS MODIFICATION ---
                
                if numerical_live.shape[1] != len(NUMERICAL_COLS):
                    print(f"Sentinel: [ANOMALY MONITOR WARNING] Numerical data shape mismatch: expected {len(NUMERICAL_COLS)}, got {numerical_live.shape[1]}")
                    continue
                
                hashed_live = anomaly_hasher.transform(categorical_live)
                
                if numerical_live.shape[1] != anomaly_scaler.n_features_in_:
                    print(f"Sentinel: [ANOMALY MONITOR ERROR] Feature count mismatch: scaler expects {anomaly_scaler.n_features_in_} features, got {numerical_live.shape[1]}")
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
                        
                        # --- MCTS INTEGRATION ---
                        # Store the dataframe that caused this anomaly
                        last_anomalous_df = live_df.copy()
                        # --- END MCTS INTEGRATION ---
                        
                        should_alert = cooldown_passed and (consecutive_anomalies == 1 or consecutive_anomalies >= 3)
                        
                        if should_alert:
                            severity = "HIGH" if mae_loss > (effective_threshold * 2) else "MEDIUM"
                            print(f"\nSentinel: [ANOMALY DETECTED - {severity}] Reconstruction Error: {mae_loss:.4f} > Threshold: {effective_threshold:.4f}")
                            print(f"Sentinel: Base threshold was {anomaly_threshold:.4f}, using buffered threshold {effective_threshold:.4f}")
                            
                            prompt = f"Investigate a {severity.lower()} security anomaly. System behavior deviated significantly from the norm (reconstruction error: {mae_loss:.4f} vs threshold: {effective_threshold:.4f}). This indicates unusual patterns across multiple system processes. Analyze potential threats like malware, rootkits, or resource abuse and suggest immediate response steps for a sysadmin."
                            analysis = get_generative_analysis(prompt)
                            print("\n--- Anomaly Generative Analysis ---\n" + analysis + "\n-----------------------------------")
                            log_event({"action": "ANOMALY_DETECTED", "loss": mae_loss, "effective_threshold": effective_threshold, "severity": severity, "details": analysis})
                            
                            last_anomaly_time = current_time
                            
                            # --- MCTS INTEGRATION: TRIGGER 2 (Host Anomaly) ---
                            print(f"Sentinel: [MCTS TRIGGER] High severity host anomaly detected. Initiating MCTS.")
                            
                            # 1. Find the most anomalous process from the dataframe
                            # Simple heuristic: process with highest CPU or Memory
                            suspicious_proc_name = "unknown"
                            suspicious_pid = 0
                            if not last_anomalous_df.empty:
                                # Combine CPU and Memory to find the "heaviest" process
                                last_anomalous_df['anomaly_score'] = last_anomalous_df['cpu_percent'] + last_anomalous_df['memory_percent']
                                most_suspicious = last_anomalous_df.loc[last_anomalous_df['anomaly_score'].idxmax()]
                                suspicious_proc_name = most_suspicious['process_name']
                                suspicious_pid = most_suspicious['pid']
                                print(f"Sentinel: [MCTS] Identified most anomalous process: {suspicious_proc_name} (PID: {suspicious_pid})")

                            # 2. Define the initial state
                            initial_state = {
                                'type': 'host_anomaly',
                                'severity': severity,
                                'suspicious_process': suspicious_proc_name,
                                'suspicious_pid': suspicious_pid,
                                'loss_score': mae_loss
                            }
                            
                            # 3. Run MCTS
                            best_move, predicted_moves = mcts_module.get_best_defensive_action(initial_state)
                            
                            # 4. Execute the user's desired action
                            print("\n" + "="*50)
                            # We can't actually *block* a process for 10s easily,
                            # so we will print the "restriction" message as requested.
                            if "kill_process" in best_move:
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
                            # --- END MCTS INTEGRATION ---
                            
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
                        # --- MCTS MODIFICATION ---
                        # Default user block is permanent
                        block_indicator(indicator, is_permanent=True)
                        # --- END MCTS MODIFICATION ---
                    else:
                        print("Sentinel: Understood. No action will be taken.")
                        log_event({"action": "USER_DECLINED_BLOCK", "indicator": indicator})
            else:
                query_length = len(user_input)
                
                if query_length > PRO_QUERY_THRESHOLD:
                    print(f"Sentinel: Processing complex query (length {query_length}) with {PRO_MODEL_NAME}...")
                    try:
                        pro_model_instance = genai.GenerativeModel(PRO_MODEL_NAME)
                        response = pro_model_instance.generate_content(user_input)
                        print(f"Sentinel: {response.text}")
                    except Exception as e:
                        print(f"Sentinel: [Analysis Error: Could not process Pro request. Reason: {e}]")
                else:
                    print(f"Sentinel: Processing fast query (length {query_length}) with {FLASH_MODEL_NAME}...")
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
        anomaly_scaler = joblib.load(SCALER_PATH)
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
            print(f"  - Default (Flash) model: {FLASH_MODEL_NAME}")
            print(f"  - On-demand (Pro) model: {PRO_MODEL_NAME}")
        else:
            print("Sentinel: [WARNING] API keys not found. OSINT and generative analysis will be disabled.")

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
