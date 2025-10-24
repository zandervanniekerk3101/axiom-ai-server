import os
import logging
import sys
import pickle # Used for saving/loading credentials
import base64 # Needed for encoding email
from email.mime.text import MIMEText # Needed for creating email message
from flask import Flask, request, jsonify, redirect, session, url_for, render_template_string
from twilio.twiml.voice_response import VoiceResponse
from twilio.rest import Client as TwilioClient # Import the Twilio Client
from openai import OpenAI
import google.oauth2.credentials
import google_auth_oauthlib.flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request # Needed for credential refresh
from googleapiclient.errors import HttpError # For Google API errors

# --- Diagnostic Print ---
# This code will run ONCE when the server boots.
# Check your Render logs for these lines.
try:
    import openai
    # Use print with flush=True to ensure it shows up in Render logs immediately
    print("🔥 Axiom AI server starting with Python version:", sys.version, flush=True)
    print(f"🔥 Detected OpenAI version: {openai.__version__}", flush=True)
except Exception as e:
    print(f"Error importing or checking OpenAI version: {e}", flush=True)
# --- End Diagnostic Print ---

# Configure logging
logging.basicConfig(level=logging.INFO)
# Get a logger instance for consistent logging
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Secret key is needed for session management during OAuth flow
# You MUST set this as an environment variable on Render
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "a_very_strong_development_secret_key_fallback")


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
# Use a persistent storage path if available (Render offers /var/data)
# For simplicity, we'll stick to the local directory, which works with Docker's file system.
TOKEN_PATH = 'token.pickle'
CLIENT_SECRETS_FILE = 'credentials.json' # This will be loaded from Render's Secret Files

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
            logger.info("Credentials loaded from token.pickle")
        except Exception as e:
            logger.error(f"Error loading token.pickle: {e}")

    # If there are no (valid) credentials available, return None (auth needed).
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                logger.info("Credentials refreshed successfully.")
                # Save the refreshed credentials
                with open(TOKEN_PATH, 'wb') as token:
                    pickle.dump(creds, token)
                google_creds = creds # Update global creds
                return creds
            except Exception as e:
                logger.error(f"Failed to refresh credentials: {e}")
                # Potentially delete token.pickle here if refresh fails permanently
                google_creds = None
                return None
        else:
            # No valid token, authorization required.
            logger.warning("No valid credentials found. Authorization required via /authorize_google")
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
             logger.warning(f"Cannot get {service_name} service: Google credentials not loaded or invalid. Need authorization via /authorize_google.")
             return None

    try:
        service = build(service_name, version, credentials=google_creds)
        logger.info(f"{service_name.capitalize()} service created successfully.")
        return service
    except HttpError as error:
        # Handle specific API errors (e.g., token revoked)
        logger.error(f"An API error occurred: {error}")
        if error.resp.status in [401, 403]:
            # Token might be revoked, clear creds to force re-auth
            google_creds = None
            if os.path.exists(TOKEN_PATH):
                os.remove(TOKEN_PATH)
            logger.error("Google API token invalid or revoked. Please re-authorize.")
        return None
    except Exception as e:
        logger.error(f"Failed to create Google service {service_name}: {e}")
        return None

# Attempt to load credentials when the server starts
# This is wrapped in a try/except to prevent boot failure if file system is read-only before start
try:
    load_google_credentials()
except Exception as e:
    logger.error(f"Error loading Google credentials on startup: {e}")
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
# This is the correct, modern way to initialize the client
openai_api_key = os.environ.get("OPENAI_API_KEY")
if not openai_api_key:
    logger.error("OPENAI_API_KEY environment variable not found.")
    openai_client = None
else:
    # THIS BLOCK IS NOW CORRECTLY INDENTED
    try:
        # THIS IS THE FIX: No 'proxies' argument
        openai_client = OpenAI(api_key=openai_api_key)
        logger.info("OpenAI client initialized successfully.")
    except Exception as e:
        # This code block will now correctly catch any *other* init errors
        logger.error(f"Failed to initialize OpenAI client: {e}")
        openai_client = None
# --- End OpenAI Setup ---

# --- Twilio Setup ---
# This is the correct, modern way to initialize the client
twilio_account_sid = os.environ.get("TWILIO_ACCOUNT_SID")
twilio_auth_token = os.environ.get("TWILIO_AUTH_TOKEN")
twilio_number = os.environ.get("TWILIO_NUMBER")
if not all([twilio_account_sid, twilio_auth_token, twilio_number]):
    logger.warning("Twilio credentials not fully set. Call functionality will be disabled.")
    twilio_client = None
else:
    try:
        # THIS IS THE FIX: No 'proxies' argument
        twilio_client = TwilioClient(twilio_account_sid, twilio_auth_token)
        logger.info("Twilio client initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize Twilio client: {e}")
        twilio_client = None
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
        # Use Flow for web apps, as we are running on a server
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE, SCOPES)

        render_url = os.environ.get("PUBLIC_BASE_URL")
        if not render_url:
            logger.error("PUBLIC_BASE_URL environment variable not set.")
            return "Server configuration error: PUBLIC_BASE_URL not set.", 500

        # Ensure redirect URI uses HTTPS as required by Google
        redirect_uri = render_url.replace("http://", "https://") + '/oauth2callback'
        
        # *** This redirect_uri MUST be listed in your Google Cloud Console ***
        # *** under "Authorized redirect URIs" for your "Web application" credential ***
        logger.info(f"Using redirect_uri: {redirect_uri}")
        flow.redirect_uri = redirect_uri

        authorization_url, state = flow.authorization_url(
            access_type='offline', # offline access gets refresh token
            include_granted_scopes='true',
            # prompt='consent' # Uncomment this if you need to force re-authentication
            )

        # Store the state so the callback can verify the auth server response.
        session['state'] = state

        logger.info(f"Redirecting user to Google for authorization: {authorization_url}")
        # Redirect the user to Google's authorization page.
        return redirect(authorization_url)
    except FileNotFoundError:
        logger.error(f"'{CLIENT_SECRETS_FILE}' not found. Check secret file setup on Render.")
        return f"Error: '{CLIENT_SECRETS_FILE}' not found. Please download it from the Google Cloud Console and place it in the server directory.", 500
    except Exception as e:
        logger.error(f"Error starting Google authorization: {e}")
        return f"Error initiating Google authorization: {e}", 500

@app.route('/oauth2callback')
def oauth2callback():
    """Handles the callback from Google after user grants permission."""
    global google_creds
    # Specify the state when creating the flow in the callback so it can be verified.
    state = session.get('state')
    if not state or state != request.args.get('state'): # Verify state
        logger.error("Authorization failed: State mismatch.")
        return "Authorization failed: State mismatch.", 400

    try:
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file( # Use Flow for web apps
            CLIENT_SECRETS_FILE, SCOPES, state=state)

        render_url = os.environ.get("PUBLIC_BASE_URL")
        if not render_url:
             logger.error("PUBLIC_BASE_URL environment variable not set during callback.")
             return "Server configuration error: PUBLIC_BASE_URL not set.", 500

        redirect_uri = render_url.replace("http://", "https://") + '/oauth2callback'
        flow.redirect_uri = redirect_uri
        logger.info(f"Callback using redirect_uri: {redirect_uri}")


        # Use the authorization server's response URL to fetch the OAuth 2.0 tokens.
        authorization_response = request.url
        # Ensure response uses https if served via proxy/load balancer
        if not authorization_response.startswith("https://"):
            authorization_response = authorization_response.replace("http://", "https://", 1)
        logger.info(f"Fetching token with response: {authorization_response}")


        flow.fetch_token(authorization_response=authorization_response)

        # Store the credentials safely.
        creds = flow.credentials
        with open(TOKEN_PATH, 'wb') as token:
            pickle.dump(creds, token)
        google_creds = creds # Update global creds
        logger.info("Authorization successful. Credentials saved to token.pickle.")
        # Redirect to home page after successful authorization
        return redirect(url_for('home'))

    except Exception as e:
        logger.error(f"Error during Google authorization callback: {e}")
        logger.exception("Detailed traceback:") # Log full traceback for debugging
        return f"Authorization failed: {e}", 500
# --- End Google Auth Routes ---


@app.route('/ask', methods=['POST'])
def ask_axiom():
    """Handles general chat prompts from the Android app."""
    if not openai_client:
        return jsonify({"error": "OpenAI client not initialized."}), 500

    data = request.get_json()
    prompt = data.get('prompt')
    logger.info(f"Received prompt from app: {prompt}")

    if not prompt:
        return jsonify({"error": "No prompt provided."}), 400

    # --- Start of simple keyword-based command parsing ---
    # This is a temporary solution. Later, we'll use OpenAI for proper intent recognition.
    
    # Check for "send email" command
    if prompt.lower().startswith("send email to"):
        try:
            parts = prompt.split("subject")
            to_part = parts[0].replace("send email to", "").strip()
            subject_part = parts[1].split("body")[0].strip()
            body_part = parts[1].split("body")[1].strip()
            
            recipient = to_part
            subject = subject_part
            body = body_part
            
            logger.info(f"Parsed email command: To={recipient}, Subject={subject}")
            result = send_email_logic(recipient, subject, body)
            return jsonify({"response": result})
        except Exception as e:
            logger.error(f"Failed to parse 'send email' prompt: {e}")
            return jsonify({"response": "Sorry, I couldn't understand the email details. Please use the format: 'send email to [email] subject [subject] body [message]'."})
    
    # Check for "make a call" command (if sent to /ask by mistake)
    if prompt.lower().startswith("make a call to"):
        try:
            parts = prompt.split("instructions:")
            # Basic parsing, very fragile
            phone_number = parts[0].replace("make a call to", "").strip()
            instructions = parts[1].strip()
            
            logger.info(f"Parsed call command: To={phone_number}")
            # This route *should* be /make_call, but we handle it here as a fallback.
            # This will fail if the phone number is invalid, as seen in user's log.
            call_status = make_call_logic(phone_number, instructions)
            # We don't have a call summary yet, so just confirm the call was started.
            return jsonify({"response": call_status})
        except Exception as e:
            logger.error(f"Failed to parse 'make a call' prompt: {e}")
            return jsonify({"response": "Sorry, I couldn't understand the call details. Please use the 'Make a Call' button in the Cyber Grid."})
            
    # --- End of simple command parsing ---


    # If no command is matched, fallback to general OpenAI chat
    try:
        completion = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are Axiom, a helpful AI business assistant. If a user asks you to perform a real-world action like sending an email or making a call, and you cannot parse the command, tell them you are just a normal AI assistant and to please use the specialized buttons in the app's Cyber Grid for those tasks."},
                {"role": "user", "content": prompt}
            ]
        )
        response_text = completion.choices[0].message.content
        logger.info(f"OpenAI response: {response_text}")
        return jsonify({"response": response_text})

    except Exception as e:
        logger.error(f"OpenAI chat failed: {e}")
        return jsonify({"error": f"Failed to get response from AI: {e}"}), 500

# --- Twilio Call Logic Routes ---
@app.route('/make_call', methods=['POST'])
def make_call_route():
    """
    Called by the Android app to *start* a call.
    It receives the phone number and instructions.
    """
    if not twilio_client:
        logger.error("Make call failed: Twilio client not initialized.")
        return jsonify({"error": "Twilio client not initialized."}), 500
        
    data = request.get_json()
    phone_number = data.get('phone_number')
    instructions = data.get('instructions')
    
    if not phone_number or not instructions:
        logger.error(f"Make call failed: Missing phone_number or instructions. Got: {data}")
        return jsonify({"error": "Missing 'phone_number' or 'instructions'."}), 400
        
    status = make_call_logic(phone_number, instructions)
    
    if "Error" in status:
        return jsonify({"error": status}), 500
    
    return jsonify({"status": "success", "message": status})

def make_call_logic(phone_number, instructions):
    """Helper function that contains the logic to initiate a Twilio call."""
    if not twilio_client:
        return "Error: Twilio is not configured on the server."
        
    try:
        # Get the public URL for the callback
        public_url = os.environ.get("PUBLIC_BASE_URL")
        if not public_url:
            logger.error("make_call_logic failed: PUBLIC_BASE_URL is not set.")
            return "Error: PUBLIC_BASE_URL is not set on the server."
            
        # URL encode the instructions to safely pass them in a URL
        encoded_instructions = base64.urlsafe_b64encode(instructions.encode('utf-8')).decode('utf-8')
        twiml_url = f"{public_url}/handle_call?instructions={encoded_instructions}"
        
        logger.info(f"Initiating call to {phone_number} with TwiML URL: {twiml_url}")

        # Make the call
        call = twilio_client.calls.create(
            to=phone_number,
            from_=twilio_number,
            url=twiml_url # Twilio will fetch instructions from this URL
        )
        
        logger.info(f"Call initiated with SID: {call.sid}")
        # Return a confirmation message to the user
        return f"Call initiated to {phone_number}. Axiom will provide a summary once the call is complete." # TODO: Add summary logic
        
    except Exception as e:
        logger.error(f"Twilio call failed: {e}")
        # Check for common Twilio error (like invalid number)
        if "is not valid" in str(e):
             return f"Error initiating call: Twilio reported the phone number '{phone_number}' is not valid. Please check the number and include the country code (e.g., +27)."
        return f"Error initiating call: {e}"

@app.route('/handle_call', methods=['POST'])
def handle_call():
    """
    Called *by Twilio* when the person answers the phone.
    It reads the instructions passed in the URL.
    """
    response = VoiceResponse()
    
    # Get the instructions from the URL query parameter
    encoded_instructions = request.args.get('instructions')
    
    if encoded_instructions:
        try:
            instructions = base64.urlsafe_b64decode(encoded_instructions).decode('utf-8')
            logger.info(f"Handling call, speaking instructions: {instructions}")
            response.say(instructions)
            
            # TODO: Add <Gather> here to collect speech input from the user
            # and send it to another endpoint for transcription and processing.
            # For now, we just say the message and hang up.
            
        except Exception as e:
            logger.error(f"Error decoding instructions for call: {e}")
            response.say("Sorry, I had an error reading my instructions.")
    else:
        logger.warning("Handling call, but no instructions were provided.")
        response.say("Hello, this is Axiom AI. I was not given a message to relay.")
        
    response.hangup() # Hang up after speaking
    return str(response)

# --- End Twilio Call Logic ---


# --- Placeholder for Gmail Logic ---
def send_email_logic(to, subject, body):
    """Helper function that contains the email sending logic."""
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
        logger.info(f"Message Id: {message['id']} sent successfully.")
        return f"OK, I've sent the email to {to} with subject '{subject}'."

    except HttpError as error:
        logger.error(f'An API error occurred while sending email: {error}')
        return f"Error sending email: {error}"
    except Exception as e:
        logger.error(f'An unexpected error occurred while sending email: {e}')
        return f"Sorry, an unexpected error occurred: {e}"
# --- End Gmail Logic ---


# --- Placeholder routes for other skills ---
@app.route('/create_doc', methods=['POST'])
def create_doc_route():
    docs_service = get_google_service('docs', 'v1')
    if not docs_service:
        return jsonify({"error": "Google API not authorized."}), 401
    # TODO: Implement Docs creation logic
    return jsonify({"status": "Document creation not implemented yet."}), 501

@app.route('/generate_title', methods=['POST'])
def generate_title():
    """
    Called by the Android app to generate a title for a new conversation.
    """
    if not openai_client:
        return jsonify({"error": "OpenAI client not initialized."}), 500
        
    data = request.get_json()
    user_message = data.get('user_message')
    axiom_message = data.get('axiom_message')
    
    if not user_message or not axiom_message:
        return jsonify({"error": "Missing messages for title generation."}), 400
        
    try:
        prompt = f"Create a very short, concise chat title (4-5 words maximum) for this conversation:\n\nUser: \"{user_message}\"\nAssistant: \"{axiom_message}\""
        
        completion = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a title generator. You only respond with a short title."},
                {"role": "user", "content": prompt}
            ]
        )
        title = completion.choices[0].message.content.strip().replace("\"", "") # Clean up quotes
        logger.info(f"Generated title: {title}")
        return jsonify({"title": title})
        
    except Exception as e:
        logger.error(f"Title generation failed: {e}")
        return jsonify({"error": f"Failed to generate title: {e}"}), 500
# --- End Placeholder routes ---


if __name__ == '__main__':
    # This block is important for local development, but Gunicorn runs the app on Render
    port = int(os.environ.get("PORT", 5000))
    # os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' # Keep commented out for Render/production
    app.run(host='0.0.0.0', port=port, debug=False)

