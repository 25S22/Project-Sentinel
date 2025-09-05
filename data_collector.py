import psutil
import csv
import time
import os
from datetime import datetime

# Configuration
CSV_FILE = "baseline_data.csv"
COLLECTION_INTERVAL_SECONDS = 2 # How often to collect data
FIELDNAMES = [
    'timestamp', 
    'pid', 
    'process_name', 
    'username', 
    'cpu_percent', 
    'memory_percent', 
    'num_threads'
    # 'net_connections' has been removed
]

def get_system_snapshot():
    """
    Gathers a list of dictionaries, where each dictionary represents
    the current state of a running process.
    """
    processes_snapshot = []
    # 'connections' has been removed from the list of attributes to fetch
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'num_threads']):
        try:
            # Get process details
            pinfo = proc.info
            processes_snapshot.append({
                'timestamp': datetime.now().isoformat(),
                'pid': pinfo['pid'],
                'process_name': pinfo['name'],
                'username': pinfo['username'],
                'cpu_percent': pinfo['cpu_percent'],
                'memory_percent': round(pinfo['memory_percent'], 2),
                'num_threads': pinfo['num_threads']
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Ignore processes that have terminated or are inaccessible
            pass
    return processes_snapshot

def start_collection():
    """
    Main function to run the data collection and write to a CSV file.
    """
    file_exists = os.path.isfile(CSV_FILE)
    
    print(f"Starting data collection... Appending to {CSV_FILE}")
    print("Press Ctrl+C to stop.")
    
    try:
        with open(CSV_FILE, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=FIELDNAMES)
            if not file_exists or os.path.getsize(CSV_FILE) == 0:
                writer.writeheader()  # Write header only if file is new/empty
            
            while True:
                snapshot = get_system_snapshot()
                if snapshot:
                    writer.writerows(snapshot)
                
                time.sleep(COLLECTION_INTERVAL_SECONDS)
                
    except KeyboardInterrupt:
        print(f"\nData collection stopped. Baseline data saved to {CSV_FILE}.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")

if __name__ == "__main__":
    start_collection()
