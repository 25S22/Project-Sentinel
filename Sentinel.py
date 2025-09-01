Of course. It's frustrating to lose your setup, but we can get it back up and running quickly. Here is a complete, one-stop guide with everything you need—from environment setup to the final code.
/UroGQw8PFC8Z3vLN/gdsUvtZNG/TmJd85ARgBobYHJXmgF0vojU/CnKoCTRRWpO
7mnKij8GffW0clitLNyDpJQjeurgYbWpSuSMPlcmwaHWz/ehUvARnGyr5urgL746X1cZVFmeY0PIPxBmB5TaUUbiA8PWD5JWAKbqQNWrkCs=
## Step 1: Recreate the Python Environment 📦
First, let's create a fresh virtual environment to keep your project's dependencies isolated.

Bash

# Navigate to your project directory
cd ~/Desktop/Project-Sentinel

# Create a new virtual environment named "sentinel-env"
python3 -m venv sentinel-env

# Activate the environment
source sentinel-env/bin/activate
Your terminal prompt should now show (sentinel-env).

## Step 2: Install All Dependencies 📚
Now, with your environment active, install all the necessary Python libraries with a single command.

Bash

pip install google-generativeai python-iptables vt-py
## Step 3: Set Your API Keys 🔑
For the script to work, you need to set your API keys as environment variables. Remember to do this every time you open a new terminal.

Bash

# Replace with your actual keys
export GEMINI_API_KEY="your-google-ai-api-key-here"
export VT_API_KEY="your-virustotal-api-key-here"
## Step 4: The Complete sentinel.py Code 🤖
This is the final, polished version of your script. Create a file named sentinel.py and paste this entire code into it.

Python

import google.generativeai as genai
import os
import sys
import socket
import iptc
import vt
import json
from datetime import datetime
from urllib.parse import urlparse

# --- CONFIGURATION ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
LOG_FILE_PATH = "sentinel_audit.log"

# --- API KEY VALIDATION ---
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY not found. Please set the environment variable. If using sudo, try 'sudo -E'.")
if not VT_API_KEY:
    raise ValueError("VT_API_KEY not found. Please set it as an environment variable. If using sudo, try 'sudo -E'.")

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-1.5-flash')

# --- HELPER FUNCTIONS ---

def log_event(data):
    """Appends a JSON object with a timestamp to the audit log file."""
    try:
        with open(LOG_FILE_PATH, 'a') as log_file:
            log_entry = {"timestamp": datetime.now().isoformat(), "event_data": data}
            log_file.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        print(f"Sentinel: [ERROR] Failed to write to log file: {e}")

def check_virustotal(url):
    """Checks the reputation of a URL using the VirusTotal API."""
    print(f"\nSentinel: Conducting OSINT on {url} via VirusTotal...")
    try:
        with vt.Client(VT_API_KEY) as client:
            url_id = vt.url_id(url)
            url_analysis = client.get_object(f"/urls/{url_id}")
            stats = url_analysis.last_analysis_stats
            malicious_votes = stats.get('malicious', 0)
            result = {"url": url, "status": "completed", "malicious_vendors": malicious_votes}
            return result
    except Exception as e:
        return {"url": url, "status": "error", "message": str(e)}

def get_generative_analysis(prompt):
    """Sends a prompt to the AI model and returns the text response."""
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"[Analysis Error: Could not process request. Reason: {e}]"

def verify_rule_exists(ip_to_check):
    """Reads the live firewall rules to confirm if a block for the IP exists."""
    try:
        table = iptc.Table(iptc.Table.FILTER)
        table.refresh()
        chain = iptc.Chain(table, "INPUT")
        for rule in chain.rules:
            if ip_to_check in rule.src:
                return True
        return False
    except Exception as e:
        print(f"Sentinel: [VERIFICATION ERROR] Could not read iptables rules: {e}")
        return False

# --- MAIN APPLICATION LOGIC ---
print("Sentinel: Greetings, I am your personal defensive agent. How can I assist you?")

while True:
    user_input = input("You > ")
    if user_input.lower() in ['exit', 'quit']:
        print("Sentinel: Shutting down. Goodbye!")
        break

    if user_input.lower().startswith("check_reputation"):
        parts = user_input.split()
        if len(parts) < 2:
            print("Sentinel: Please provide a URL. Usage: check_reputation <URL>")
            continue
        
        url_to_check = parts[1]
        
        # --- STEP 1: VIRUSTOTAL CHECK ---
        vt_result = check_virustotal(url_to_check)
        log_event(vt_result)

        if vt_result["status"] == "error":
            print(f"Sentinel: [ERROR] OSINT failed. Reason: {vt_result['message']}")
            continue
            
        malicious_count = vt_result['malicious_vendors']
        print(f"Sentinel: OSINT complete. VirusTotal reports {malicious_count} malicious detections.")

        # --- STEP 2: CONTEXT-AWARE GENERATIVE ANALYSIS ---
        print(f"\nSentinel: Performing generative analysis...")
        
        if malicious_count > 0:
            # Prompt for MALICIOUS sites: Focus on overview first, then threat details.
            analysis_prompt = f"""
            Analyze the website '{url_to_check}'.

            1.  **Overview:** First, briefly describe the website's stated purpose. What kind of business or service does it claim to be?

            2.  **Threat Analysis:** More importantly, this site was flagged with {malicious_count} malicious detections by security scanners. Provide a detailed analysis of the likely threats. Explain why it is considered malicious (e.g., phishing, malware, scam) and describe the potential risks to a user who visits it.
            """
        else:
            # Prompt for CLEAN sites: Focus heavily on the business/content overview.
            analysis_prompt = f"""
            Analyze the website '{url_to_check}'.

            1.  **Detailed Overview:** Focus primarily on providing a detailed overview of the website. What is it about? What is the business or organization behind it? What specific products, services, or content does it offer?

            2.  **Security Reputation:** Conclude with a brief mention of its security reputation, noting that it was not flagged by security scanners.
            """
        
        analysis_text = get_generative_analysis(analysis_prompt)
        print("--- Generative Analysis ---")
        print(analysis_text)
        print("---------------------------")
        
        # --- STEP 3: HUMAN-IN-THE-LOOP BLOCKING (IF MALICIOUS) ---
        if malicious_count > 0:
            confirmation = input("\nSentinel: Threat detected. Would you like me to block this URL? (yes/no) > ")
            if confirmation.lower() == 'yes':
                try:
                    parsed_url = urlparse(url_to_check)
                    hostname_to_block = parsed_url.hostname
                    if not hostname_to_block:
                        raise ValueError("Could not extract a valid hostname from the URL.")
                    ip_to_block = socket.gethostbyname(hostname_to_block)
                    
                    print(f"Sentinel: Attempting to apply firewall block for IP: {ip_to_block}...")
                    table = iptc.Table(iptc.Table.FILTER)
                    table.autocommit = True
                    chain = iptc.Chain(table, "INPUT")
                    rule = iptc.Rule()
                    rule.src = ip_to_block
                    rule.target = iptc.Target(rule, "DROP")
                    chain.insert_rule(rule)

                    print("Sentinel: Verifying block implementation...")
                    if verify_rule_exists(ip_to_block):
                        success_message = f"VERIFICATION SUCCESS: Firewall rule for {ip_to_block} is active."
                        print(f"Sentinel: {success_message}")
                        log_event({"action": "BLOCK_IP_VERIFIED", "details": success_message})
                    else:
                        failure_message = f"VERIFICATION FAILED: Rule for {ip_to_block} was NOT added."
                        print(f"Sentinel: {failure_message}")
                        log_event({"action": "BLOCK_IP_FAILED", "details": failure_message})

                except Exception as e:
                    error_message = f"An unexpected error occurred during the block action: {e}"
                    print(f"Sentinel: [ERROR] {error_message}")
                    log_event({"action": "BLOCK_IP_EXCEPTION", "details": error_message})
            else:
                print("Sentinel: Understood. No action will be taken.")
                log_event({"action": "USER_DECLINED_BLOCK", "url": url_to_check})
    else:
        # For all other general queries
        print("Sentinel: Processing general query...")
        response_text = get_generative_analysis(user_input)
        print(f"Sentinel: {response_text}")

## Step 5: Run Sentinel Correctly ▶️
With the environment active and keys set, run the script using the full, correct command.

Bash

sudo -E sentinel-env/bin/python sentinel.py
That's it! Following these five steps will completely restore your project and get you running again.
