import os
import logging
import sys
import pickle # Used for saving/loading credentials
from flask import Flask, request, jsonify, redirect, session, url_for
from twilio.twiml.voice_response import VoiceResponse
from openai import OpenAI
import google.oauth2.credentials
import google_auth_oauthlib.flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request # Needed for credential refresh

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
# In production, use a strong, randomly generated secret key stored securely
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
TOKEN_PATH = 'token.pickle' # Changed to pickle for better object storage
CLIENT_SECRETS_FILE = 'credentials.json'

google_creds = None

def load_google_credentials():
    """Loads existing Google credentials from storage or initiates auth flow."""
    global google_creds
    creds = None
    # The file token.pickle stores the user's access and refresh tokens.
    if os.path.exists(TOKEN_PATH):
        try:
            with open(TOKEN_PATH, 'rb') as token:
                creds = pickle.load(token)
                logging.info("Credentials loaded from token.pickle")
        except Exception as e:
            logging.error(f"Error loading token.pickle: {e}")

    # If there are no (valid) credentials available, return None (auth needed).
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                logging.info("Credentials refreshed successfully.")
                # Save the refreshed credentials
                with open(TOKEN_PATH, 'wb') as token:
                    pickle.dump(creds, token)
                google_creds = creds # Update global creds
                return creds
            except Exception as e:
                logging.error(f"Failed to refresh credentials: {e}")
                # Potentially delete token.pickle here if refresh fails permanently
                google_creds = None
                return None
        else:
            # No valid token, authorization required.
            logging.warning("No valid credentials found. Authorization required via /authorize_google")
            google_creds = None
            return None
    google_creds = creds # Update global creds
    return creds

def get_google_service(service_name, version):
    """Builds and returns an authorized Google API service object."""
    global google_creds
    if not google_creds or not google_creds.valid:
        # Try loading/refreshing first
        load_google_credentials()
        # If still not valid after trying, return None
        if not google_creds or not google_creds.valid:
             logging.warning(f"Cannot get {service_name} service: Google credentials not loaded or invalid. Need authorization via /authorize_google.")
             return None

    try:
        service = build(service_name, version, credentials=google_creds)
        logging.info(f"{service_name.capitalize()} service created successfully.")
        return service
    except Exception as e:
        logging.error(f"Failed to create Google service {service_name}: {e}")
        return None

# Attempt to load credentials when the server starts
load_google_credentials()
# --- End Google API Setup ---


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
        # Create flow instance to manage the OAuth 2.0 flow.
        flow = google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file(
            CLIENT_SECRETS_FILE, SCOPES)

        # The URI created here must exactly match one of the authorized redirect URIs
        # configured in the Cloud Console. Since this runs locally during auth setup,
        # we often use localhost. For Render, we need the public URL.
        # **IMPORTANT**: You MUST add this callback URL to your OAuth Client ID settings
        # in Google Cloud Console under "Authorized redirect URIs".
        # For local testing use: http://localhost:5000/oauth2callback
        # For Render deployment use: https://your-render-service-name.onrender.com/oauth2callback
        render_url = os.environ.get("PUBLIC_BASE_URL") # Reuse existing env var if set
        if render_url:
             # Use replace for https if render_url starts with http
             redirect_uri = render_url.replace("http://", "https://") + '/oauth2callback'
        else:
            # Fallback for local testing (adjust port if needed)
             redirect_uri = url_for('oauth2callback', _external=True)

        flow.redirect_uri = redirect_uri

        authorization_url, state = flow.authorization_url(
            access_type='offline', # offline access gets refresh token
            include_granted_scopes='true')

        # Store the state so the callback can verify the auth server response.
        session['state'] = state

        logging.info(f"Redirecting user to Google for authorization: {authorization_url}")
        # Redirect the user to Google's authorization page.
        return redirect(authorization_url)
    except FileNotFoundError:
        logging.error(f"'{CLIENT_SECRETS_FILE}' not found. Download it from Google Cloud Console.")
        return f"Error: '{CLIENT_SECRETS_FILE}' not found. Please download it from the Google Cloud Console and place it in the server directory.", 500
    except Exception as e:
        logging.error(f"Error starting Google authorization: {e}")
        return f"Error initiating Google authorization: {e}", 500

@app.route('/oauth2callback')
def oauth2callback():
    """Handles the callback from Google after user grants permission."""
    global google_creds
    # Specify the state when creating the flow in the callback so it can be verified.
    state = session.get('state')
    if not state:
        return "Authorization failed: State missing from session.", 400

    try:
        flow = google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file(
            CLIENT_SECRETS_FILE, SCOPES, state=state)

        # Rebuild the redirect_uri used in the initial authorization request
        render_url = os.environ.get("PUBLIC_BASE_URL")
        if render_url:
            redirect_uri = render_url.replace("http://", "https://") + '/oauth2callback'
        else:
            # Fallback for local testing (adjust port if needed)
             redirect_uri = url_for('oauth2callback', _external=True)
        flow.redirect_uri = redirect_uri


        # Use the authorization server's response URL to fetch the OAuth 2.0 tokens.
        authorization_response = request.url
        # On Render/production with HTTPS, ensure the response uses https
        if not authorization_response.startswith("https://") and render_url:
             authorization_response = authorization_response.replace("http://", "https://", 1)

        flow.fetch_token(authorization_response=authorization_response)

        # Store the credentials safely.
        creds = flow.credentials
        with open(TOKEN_PATH, 'wb') as token:
            pickle.dump(creds, token)
        google_creds = creds # Update global creds
        logging.info("Authorization successful. Credentials saved to token.pickle.")
        return "Authorization successful! You can close this window."

    except Exception as e:
        logging.error(f"Error during Google authorization callback: {e}")
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

    # --- TODO: Check if prompt is a command for Google API ---
    # Example: if "send email to" in prompt.lower():
    #     # Parse email details (to, subject, body) using OpenAI or simple logic
    #     # Call send_email function (which uses get_google_service)
    #     # return jsonify({"response": "OK, I've sent the email."})
    # else if "schedule meeting" in prompt.lower():
        # ... handle calendar ...
    # else:
        # Fallback to general OpenAI chat

    try:
        # Send the prompt to OpenAI
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


# --- Placeholder routes for new skills ---
@app.route('/send_email', methods=['POST'])
def send_email_route():
    gmail_service = get_google_service('gmail', 'v1')
    if not gmail_service:
        return jsonify({"error": "Google API not authorized."}), 401

    # Basic example - replace with actual logic
    # data = request.get_json()
    # to = data.get('to')
    # subject = data.get('subject')
    # body = data.get('body')
    # Use gmail_service.users().messages().send(...)
    return jsonify({"status": "Email sending not fully implemented yet."}), 501

@app.route('/create_doc', methods=['POST'])
def create_doc_route():
    docs_service = get_google_service('docs', 'v1')
    if not docs_service:
        return jsonify({"error": "Google API not authorized."}), 401
    # Use docs_service.documents().create(...)
    return jsonify({"status": "Document creation not fully implemented yet."}), 501

# --- End Placeholder routes ---


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    # Important for OAuthlib Redirect URI matching in local testing:
    # os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' # ONLY use for local testing with HTTP
    app.run(host='0.0.0.0', port=port, debug=False)

