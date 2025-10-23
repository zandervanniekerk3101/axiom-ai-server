import os
import logging
import sys
import pickle
import base64
from email.mime.text import MIMEText
from flask import Flask, request, jsonify, redirect, session, url_for
from twilio.rest import Client as TwilioClient # Import Twilio Client
from twilio.twiml.voice_response import VoiceResponse
from openai import OpenAI
import google.oauth2.credentials
import google_auth_oauthlib.flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from googleapiclient.errors import HttpError
import urllib.parse # Needed to encode instructions for the URL

# --- Diagnostic Print ---
try:
    import openai
    print(f"🔥 Axiom AI server starting with Python version: {sys.version}")
    print(f"🔥 Detected OpenAI version: {openai.__version__}")
except Exception as e:
    print(f"Error importing or checking OpenAI version: {e}")
# --- End Diagnostic Print ---

# Configure logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret_key_replace_me")

# --- Google API Setup ---
SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/documents',
    'https://www.googleapis.com/auth/spreadsheets',
    'https://www.googleapis.com/auth/presentations',
    'https://www.googleapis.com/auth/calendar.events',
    'https://www.googleapis.com/auth/forms.body'
]
TOKEN_PATH = 'token.pickle'
CLIENT_SECRETS_FILE = 'credentials.json'
google_creds = None

# --- OpenAI Setup ---
openai_api_key = os.environ.get("OPENAI_API_KEY")
if not openai_api_key:
    logging.error("OPENAI_API_KEY environment variable not found.")
    openai_client = None
else:
    try:
        openai_client = OpenAI(api_key=openai_api_key)
        logging.info("OpenAI client initialized successfully.")
    except Exception as e:
        logging.error(f"Failed to initialize OpenAI client: {e}")
        openai_client = None

# --- Twilio Setup ---
twilio_account_sid = os.environ.get("TWILIO_ACCOUNT_SID")
twilio_auth_token = os.environ.get("TWILIO_AUTH_TOKEN")
twilio_number = os.environ.get("TWILIO_NUMBER")
public_base_url = os.environ.get("PUBLIC_BASE_URL") # We need this!

if not all([twilio_account_sid, twilio_auth_token, twilio_number, public_base_url]):
    logging.error("Twilio environment variables (SID, TOKEN, NUMBER, PUBLIC_BASE_URL) are not all set.")
    twilio_client = None
else:
    try:
        twilio_client = TwilioClient(twilio_account_sid, twilio_auth_token)
        logging.info("Twilio client initialized successfully.")
    except Exception as e:
        logging.error(f"Failed to initialize Twilio client: {e}")
        twilio_client = None
# --- End Twilio Setup ---


# ... (Keep all existing Google helper functions: load_google_credentials, get_google_service, create_message) ...
def load_google_credentials():
# ... (existing code) ...
# ... (existing code) ...
# ... (existing code) ...
    return creds

def get_google_service(service_name, version):
# ... (existing code) ...
# ... (existing code) ...
# ... (existing code) ...
        return None

load_google_credentials()

def create_message(sender, to, subject, message_text):
# ... (existing code) ...
# ... (existing code) ...
# ... (existing code) ...
  return {'raw': raw_message}
# --- End Google Helper Functions ---


@app.route('/')
def home():
    auth_status = "Google API Authorized" if google_creds and google_creds.valid else "Google API NOT Authorized (Visit /authorize_google)"
    return f"Axiom AI Server is running.<br>{auth_status}"

# --- Google Auth Routes ---
@app.route('/authorize_google')
def authorize_google():
# ... (existing code) ...
# ... (existing code) ...
# ... (existing code) ...
        return redirect(authorization_url)
    except Exception as e:
        return f"Error initiating Google authorization: {e}", 500

@app.route('/oauth2callback')
def oauth2callback():
# ... (existing code) ...
# ... (existing code) ...
# ... (existing code) ...
        return redirect(url_for('home'))
    except Exception as e:
        return f"Authorization failed: {e}", 500
# --- End Google Auth Routes ---


@app.route('/ask', methods=['POST'])
def ask_axiom():
# ... (existing code) ...
# ... (existing code) ...
# ... (We will remove the simple "send email" check from here later) ...
    if not prompt:
        return jsonify({"error": "No prompt provided."}), 400

    # --- TODO: Add sophisticated command parsing here ---
    # We will improve this later. For now, it's just a chatbot.

    try:
        completion = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are Axiom, a helpful AI business assistant."},
                {"role": "user", "content": prompt}
            ]
        )
        response_text = completion.choices[0].message.content
        logging.info(f"OpenAI response: {response_text}")
        return jsonify({"response": response_text})
    except Exception as e:
        logging.error(f"OpenAI chat failed: {e}")
        return jsonify({"error": f"Failed to get response from AI: {e}"}), 500


# --- NEW: Twilio Call Routes ---
@app.route('/make_call', methods=['POST'])
def make_call_route():
    """
    Receives a phone number and instructions from the Android app
    and initiates a Twilio call.
    """
    if not twilio_client:
        logging.error("Make call failed: Twilio client not initialized.")
        return jsonify({"error": "Twilio client not initialized on server."}), 500

    data = request.get_json()
    phone_number = data.get('phone_number')
    instructions = data.get('instructions')

    if not phone_number or not instructions:
        return jsonify({"error": "Missing phone_number or instructions."}), 400

    logging.info(f"Received call request for: {phone_number} with instructions: {instructions}")

    try:
        # URL-encode the instructions to safely pass them in a URL
        encoded_instructions = urllib.parse.quote(instructions)
        
        # Create the full URL for Twilio to fetch its TwiML instructions
        # This tells Twilio: "When the person answers, call *this* URL"
        twiml_url = f"{public_base_url}/handle_call?instructions={encoded_instructions}"
        
        logging.info(f"Initiating call with TwiML URL: {twiml_url}")

        call = twilio_client.calls.create(
            to=phone_number,
            from_=twilio_number,
            url=twiml_url # The "what to do" URL
            # We can add 'StatusCallback' here later to get a summary
        )
        
        logging.info(f"Call initiated with SID: {call.sid}")
        # Send a success response back to the Android app
        return jsonify({"response": f"Call initiated to {phone_number}. Axiom will report back when complete."})

    except Exception as e:
        logging.error(f"Twilio call failed: {e}")
        return jsonify({"error": f"Twilio call failed: {e}"}), 500

@app.route('/handle_call', methods=['POST'])
def handle_call_twiml():
    """
    This route is called *by Twilio* when the person answers the phone.
    It reads the instructions from the URL and generates TwiML to speak them.
    """
    instructions = request.args.get('instructions', "Hello, Axiom AI is calling. No instructions were provided.")
    logging.info(f"Twilio /handle_call route hit. Speaking: {instructions}")

    response = VoiceResponse()
    response.say(instructions)
    response.say("Thank you, goodbye.")
    response.hangup()

    return str(response), 200, {'Content-Type': 'text/xml'}
# --- End Twilio Call Routes ---


# --- Google Helper Functions & Routes ---
def send_email_logic(to, subject, body):
# ... (existing code) ...
# ... (existing code) ...
# ... (existing code) ...
        return f"Sorry, an unexpected error occurred while trying to send the email: {e}"

@app.route('/send_email', methods=['POST'])
def send_email_route():
# ... (existing code) ...
# ... (existing code) ...
# ... (existing code) ...
        return jsonify({"status": "success", "message": result})

@app.route('/create_doc', methods=['POST'])
def create_doc_route():
# ... (existing code) ...
# ... (existing code) ...
    return jsonify({"status": "Document creation not implemented yet."}), 501
# --- End Google Routes ---


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

