import time
import json
import csv
import subprocess
from datetime import datetime

# --- CONFIGURATION ---
# We no longer read from a static file, we will stream from journalctl
OUTPUT_CSV_FILE = 'baseline_data.csv' # The structured dataset for our ML model
CAPTURE_DURATION_SECONDS = 3600  # Run for 1 hour to start

def capture_baseline_data():
    """
    Monitors the systemd journal for a set duration and saves parsed data to a CSV.
    """
    print("Starting data collection from systemd journal via journalctl...")
    print(f"This will run for {CAPTURE_DURATION_SECONDS / 60:.0f} minutes.")
    
    start_time = time.time()
    
    # The command to stream new journal entries in JSON format
    command = ['journalctl', '-f', '-o', 'json']
    
    try:
        # Open the output CSV file for writing
        with open(OUTPUT_CSV_FILE, 'w', newline='') as csvfile:
            fieldnames = ['timestamp', 'process_name', 'pid', 'message']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # Start the journalctl process
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Read from the process's output stream
            for line in iter(process.stdout.readline, ''):
                if time.time() - start_time > CAPTURE_DURATION_SECONDS:
                    print("\nCapture duration reached. Stopping data collection...")
                    break
                
                if line:
                    try:
                        log_entry = json.loads(line)
                        
                        # Extract relevant fields from the JSON output
                        # We use .get() to avoid errors if a key is missing
                        timestamp_usec = int(log_entry.get('__REALTIME_TIMESTAMP', 0))
                        dt_object = datetime.fromtimestamp(timestamp_usec / 1000000)
                        
                        parsed_data = {
                            'timestamp': dt_object.isoformat(),
                            'process_name': log_entry.get('SYSLOG_IDENTIFIER', 'N/A'),
                            'pid': log_entry.get('_PID', 'N/A'),
                            'message': log_entry.get('MESSAGE', '')
                        }
                        writer.writerow(parsed_data)
                    except json.JSONDecodeError:
                        # Ignore lines that are not valid JSON
                        continue
            
            # Clean up the process
            process.terminate()

    except FileNotFoundError:
        print("[ERROR] 'journalctl' command not found. Please ensure systemd is installed.")
        return
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")

    print(f"\nData collection complete. Baseline data saved to {OUTPUT_CSV_FILE}")


if __name__ == '__main__':
    # This script still needs sudo to run journalctl without restrictions
    capture_baseline_data()
