import time
import re
import csv
from datetime import datetime

# --- CONFIGURATION ---
SOURCE_LOG_FILE = '/var/log/syslog'  # The log file we will monitor
OUTPUT_CSV_FILE = 'baseline_data.csv' # The structured dataset for our ML model
CAPTURE_DURATION_SECONDS = 3600  # Run for 1 hour to start

def parse_syslog_line(line):
    """
    Parses a single line from syslog to extract key features.
    This is a simple parser; it can be made more complex later.
    """
    # Example syslog line: Sep  1 23:30:01 death-vbox CRON[12345]: (root) CMD (command...)
    match = re.search(r'(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+[\w-]+\s+([\w-]+)\[?(\d*)?\]?:', line)
    
    if match:
        timestamp_str, process_name, pid = match.groups()
        
        # We need a consistent timestamp format
        # This parsing is specific to the default syslog format and might need adjustment
        dt_object = datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
        # Add the current year
        dt_object = dt_object.replace(year=datetime.now().year)
        
        return {
            'timestamp': dt_object.isoformat(),
            'process_name': process_name,
            'pid': pid if pid else 'N/A'
        }
    return None

def capture_baseline_data():
    """
    Monitors a log file for a set duration and saves parsed data to a CSV.
    """
    print(f"Starting data collection from {SOURCE_LOG_FILE}...")
    print(f"This will run for {CAPTURE_DURATION_SECONDS / 60:.0f} minutes.")
    
    start_time = time.time()
    
    # Open the output CSV file for writing
    with open(OUTPUT_CSV_FILE, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'process_name', 'pid']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        # Open the source log file for reading
        try:
            with open(SOURCE_LOG_FILE, 'r') as logfile:
                logfile.seek(0, 2) # Go to the end
                
                while time.time() - start_time < CAPTURE_DURATION_SECONDS:
                    line = logfile.readline()
                    if line:
                        parsed_data = parse_syslog_line(line)
                        if parsed_data:
                            writer.writerow(parsed_data)
                    else:
                        # No new lines, wait a moment
                        time.sleep(0.1)
        except FileNotFoundError:
            print(f"[ERROR] Log file not found at {SOURCE_LOG_FILE}. Please check the path.")
            return
        except Exception as e:
            print(f"[ERROR] An unexpected error occurred: {e}")

    print(f"\nData collection complete. Baseline data saved to {OUTPUT_CSV_FILE}")

if __name__ == '__main__':
    # Important: This script needs to read system logs, so it might require sudo
    capture_baseline_data()
