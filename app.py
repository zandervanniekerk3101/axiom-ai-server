import os
import logging
import sys
import pickle # Used for saving/loading credentials
import base64 # Needed for encoding email
from email.mime.text import MIMEText # Needed for creating email message
from flask import Flask, request, jsonify, redirect, session, url_for
from twilio.twiml.voice_response import VoiceResponse
from openai import OpenAI
import google.oauth2.credentials
import google_auth_oauthlib.flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request # Needed for credential refresh
from googleapiclient.errors import HttpError # For Google API errors


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
# Secret key is needed for session management during OAuth flow
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

def load_google_credentials():
    """Loads existing Google credentials from storage or initiates auth flow."""
    global google_creds
    creds = None
    if os.path.exists(TOKEN_PATH):
        try:
            with open(TOKEN_PATH, 'rb') as token:
                creds = pickle.load(token)
                logging.info("Credentials loaded from token.pickle")
        except Exception as e:
            logging.error(f"Error loading token.pickle: {e}")

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                logging.info("Credentials refreshed successfully.")
                with open(TOKEN_PATH, 'wb') as token:
                    pickle.dump(creds, token)
                google_creds = creds
                return creds
            except Exception as e:
                logging.error(f"Failed to refresh credentials: {e}")
                google_creds = None
                return None
        else:
            logging.warning("No valid credentials found. Authorization required via /authorize_google")
            google_creds = None
            return None
    google_creds = creds
    return creds

def get_google_service(service_name, version):
    """Builds and returns an authorized Google API service object."""
    global google_creds
    if not google_creds or not google_creds.valid:
        load_google_credentials()
        if not google_creds or not google_creds.valid:
             logging.warning(f"Cannot get {service_name} service: Google credentials not loaded or invalid. Need authorization via /authorize_google.")
             return None
    try:
        service = build(service_name, version, credentials=google_creds)
        logging.info(f"{service_name.capitalize()} service created successfully.")
        return service
    except HttpError as error:
        logging.error(f"An API error occurred: {error}")
        # Handle specific errors, e.g., re-authentication if token revoked
        return None
    except Exception as e:
        logging.error(f"Failed to create Google service {service_name}: {e}")
        return None

# Attempt to load credentials when the server starts
load_google_credentials()
# --- End Google API Setup ---

# --- Helper function for Gmail ---
def create_message(sender, to, subject, message_text):
  """Create a message for an email.

  Args:
    sender: Email address of the sender.
    to: Email address of the receiver.
    subject: The subject of the email message.
    message_text: The text of the email message.

  Returns:
    An object containing a base64url encoded email object.
  """
  message = MIMEText(message_text)
  message['to'] = to
  message['from'] = sender
  message['subject'] = subject
  # Encode the message in base64url format. Required by Gmail API
  raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
  return {'raw': raw_message}

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
# --- End OpenAI Setup ---

# --- Twilio Setup ---
# (Credentials handled by library via environment variables)
# --- End Twilio Setup ---


@app.route('/')
def home():
    """Basic route to check if the server is running."""
    auth_status = "Google API Authorized" if google_creds and google_creds.valid else "Google API NOT Authorized (Visit /authorize_google)"
    return f"Axiom AI Server is running.<br>{auth_status}"

# --- Google Auth Routes ---
@app.route('/authorize_google')
def authorize_google():
    """Starts the Google OAuth 2.0 authorization flow."""
    try:
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file( # Use Flow for web apps
            CLIENT_SECRETS_FILE, SCOPES)

        render_url = os.environ.get("PUBLIC_BASE_URL")
        if not render_url:
            logging.error("PUBLIC_BASE_URL environment variable not set.")
            return "Server configuration error: PUBLIC_BASE_URL not set.", 500

        # Ensure redirect URI uses HTTPS
        redirect_uri = render_url.replace("http://", "https://") + '/oauth2callback'

        # *** IMPORTANT: Check if redirect_uri is registered in Google Cloud Console ***
        logging.info(f"Using redirect_uri: {redirect_uri}")
        flow.redirect_uri = redirect_uri

        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            # Add prompt='consent' to force re-consent and get a refresh token
            # every time, useful during development. Remove for production.
            prompt='consent'
            )

        session['state'] = state
        logging.info(f"Redirecting user to Google for authorization: {authorization_url}")
        return redirect(authorization_url)
    except FileNotFoundError:
        logging.error(f"'{CLIENT_SECRETS_FILE}' not found. Check secret file setup on Render.")
        return f"Error: '{CLIENT_SECRETS_FILE}' not found.", 500
    except Exception as e:
        logging.error(f"Error starting Google authorization: {e}")
        return f"Error initiating Google authorization: {e}", 500

@app.route('/oauth2callback')
def oauth2callback():
    """Handles the callback from Google after user grants permission."""
    global google_creds
    state = session.get('state')
    if not state or state != request.args.get('state'): # Verify state
        logging.error("Authorization failed: State mismatch.")
        return "Authorization failed: State mismatch.", 400

    try:
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file( # Use Flow for web apps
            CLIENT_SECRETS_FILE, SCOPES, state=state)

        render_url = os.environ.get("PUBLIC_BASE_URL")
        if not render_url:
             logging.error("PUBLIC_BASE_URL environment variable not set during callback.")
             return "Server configuration error: PUBLIC_BASE_URL not set.", 500

        redirect_uri = render_url.replace("http://", "https://") + '/oauth2callback'
        flow.redirect_uri = redirect_uri
        logging.info(f"Callback using redirect_uri: {redirect_uri}")


        authorization_response = request.url
        # Ensure response uses https if served via proxy/load balancer
        if not authorization_response.startswith("https://"):
            authorization_response = authorization_response.replace("http://", "https://", 1)
        logging.info(f"Fetching token with response: {authorization_response}")


        flow.fetch_token(authorization_response=authorization_response)

        creds = flow.credentials
        with open(TOKEN_PATH, 'wb') as token:
            pickle.dump(creds, token)
        google_creds = creds
        logging.info("Authorization successful. Credentials saved to token.pickle.")
        # Redirect to home page after successful authorization
        return redirect(url_for('home'))

    except Exception as e:
        logging.error(f"Error during Google authorization callback: {e}")
        logging.exception("Detailed traceback:") # Log full traceback for debugging
        return f"Authorization failed: {e}", 500
# --- End Google Auth Routes ---


@app.route('/ask', methods=['POST'])
def ask_axiom():
    """Handles questions (text or transcribed speech) from the Android app."""
    if not openai_client:
        return jsonify({"error": "OpenAI client not initialized."}), 500

    data = request.get_json()
    prompt = data.get('prompt')
    logging.info(f"Received prompt from app: {prompt}")

    if not prompt:
        return jsonify({"error": "No prompt provided."}), 400

    # --- TODO: Add sophisticated command parsing here ---
    # Example using OpenAI to determine intent and extract parameters
    # if intent == "send_email":
    #    to = parameters.get('recipient')
    #    subject = parameters.get('subject')
    #    body = parameters.get('body')
    #    result = send_email_logic(to, subject, body) # Call helper
    #    return jsonify({"response": result})

    # Simple keyword check for now
    if prompt.lower().startswith("send email"):
        # Very basic parsing - NEEDS IMPROVEMENT
        try:
            parts = prompt.split("to")
            recipient_part = parts[1].split("subject")[0].strip()
            subject_part = parts[1].split("subject")[1].split("body")[0].strip()
            body_part = parts[1].split("body")[1].strip()
            logging.info(f"Attempting to send email: To={recipient_part}, Subject={subject_part}, Body={body_part}")
            result = send_email_logic(recipient_part, subject_part, body_part)
            return jsonify({"response": result})
        except Exception as e:
            logging.error(f"Failed to parse email prompt: {e}")
            return jsonify({"response": "Sorry, I couldn't understand the email details. Please try formatting like 'send email to recipient@example.com subject Your Subject body Your message'."})

    # --- Fallback to general OpenAI chat ---
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


@app.route('/incoming_call', methods=['POST'])
def handle_incoming_call():
    """Handles incoming calls via Twilio."""
    response = VoiceResponse()
    response.say("Hello, you have reached Axiom AI. How can I help you today?")
    response.hangup() # Hang up for now
    return str(response)

# --- Helper function containing the email sending logic ---
def send_email_logic(to, subject, body):
    gmail_service = get_google_service('gmail', 'v1')
    if not gmail_service:
        return "Error: Could not access Gmail. Please ensure Google API is authorized."

    try:
        # Get the user's email address (usually 'me')
        user_profile = gmail_service.users().getProfile(userId='me').execute()
        sender_email = user_profile['emailAddress']
        if not sender_email:
             return "Error: Could not determine sender email address."

        message_body = create_message(sender_email, to, subject, body)

        # Send the message
        message = (gmail_service.users().messages().send(userId='me', body=message_body)
                   .execute())
        logging.info(f"Message Id: {message['id']} sent successfully.")
        return f"OK, I've sent the email to {to} with subject '{subject}'."

    except HttpError as error:
        logging.error(f'An API error occurred while sending email: {error}')
        return f"Error sending email: {error}"
    except Exception as e:
        logging.error(f'An unexpected error occurred while sending email: {e}')
        return f"Sorry, an unexpected error occurred while trying to send the email: {e}"
# --- End Helper ---

# --- Placeholder route (less direct use now, logic moved to helper) ---
@app.route('/send_email', methods=['POST'])
def send_email_route():
    # This route could be used for direct API calls if needed,
    # but the primary logic is now triggered via the /ask route.
    # We still need to parse data if called directly.
    data = request.get_json()
    to = data.get('to')
    subject = data.get('subject')
    body = data.get('body')

    if not all([to, subject, body]):
         return jsonify({"error": "Missing 'to', 'subject', or 'body' in request."}), 400

    result = send_email_logic(to, subject, body)
    if "Error" in result:
        return jsonify({"error": result}), 500
    else:
        return jsonify({"status": "success", "message": result})


@app.route('/create_doc', methods=['POST'])
def create_doc_route():
    docs_service = get_google_service('docs', 'v1')
    if not docs_service:
        return jsonify({"error": "Google API not authorized."}), 401
    # TODO: Implement Docs creation logic
    return jsonify({"status": "Document creation not implemented yet."}), 501

# --- End Placeholder routes ---


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    # os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' # Keep commented out for Render
    app.run(host='0.0.0.0', port=port, debug=False)

