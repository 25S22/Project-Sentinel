Of course. Here is a simple Python script to test your API connection.

Since you've already exported your API key to your terminal environment, this script will automatically pick it up.

1. Create the Python file
First, create a new file named test_api.py and add the following code to it.

Python

import os
import google.generativeai as genai

# Configure the API key
# The key is automatically read from the GOOGLE_API_KEY environment variable
try:
    genai.configure(api_key=os.environ["GOOGLE_API_KEY"])
except KeyError:
    print("🔴 GOOGLE_API_KEY environment variable not set.")
    exit()

# Create the model
model = genai.GenerativeModel('gemini-pro')

# Send a prompt and get the response
try:
    print("Sending prompt to the API...")
    response = model.generate_content("Tell me a short, one-sentence joke.")
    
    # Print the response text
    print("✅ Success!")
    print("Response:", response.text)

except Exception as e:
    print("🔴 An error occurred:", e)

2. Run the script
Open your terminal in the same directory where you saved test_api.py and run the following command:

Bash

python test_api.py
3. Check the output
If your API key is configured correctly and the connection is successful, you should see an output similar to this:

Sending prompt to the API...
✅ Success!
Response: Why don't cats play poker in the jungle? Too many cheetahs!
This confirms that your environment is set up correctly and you can successfully communicate with the Google Generative AI API. If you see an error, it will most likely be related to the API key not being set correctly in your environment.
