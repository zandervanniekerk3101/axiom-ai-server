import os
import logging
import sys
import pickle
import base64 # NEW: For encoding audio
from email.mime.text import MIMEText
from flask import Flask, request, jsonify, redirect, session, url_for
from twilio.twiml.voice_response import VoiceResponse
from twilio.rest import Client as TwilioClient
from openai import OpenAI
# UPDATED ElevenLabs Imports
from elevenlabs import Voice, VoiceSettings
from elevenlabs.client import ElevenLabs
# REMOVED: from elevenlabs import play (not needed on server)
import google.oauth2.credentials
import google_auth_oauthlib.flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from googleapiclient.errors import HttpError

# ... (rest of imports and setup remain the same) ...

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret_key_replace_me")

# ... (Google API Setup remains the same) ...
# ... (Gmail Helper remains the same) ...
# ... (OpenAI Setup remains the same) ...

# --- ElevenLabs Setup ---
elevenlabs_api_key = os.environ.get("ELEVENLABS_API_KEY")
elevenlabs_voice_id = os.environ.get("ELEVENLABS_VOICE_ID")
if not elevenlabs_api_key or not elevenlabs_voice_id:
    logger.warning("ElevenLabs credentials not set. Audio generation will be disabled.")
    elevenlabs_client = None
else:
    try:
        elevenlabs_client = ElevenLabs(api_key=elevenlabs_api_key)
        logger.info("ElevenLabs client initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize ElevenLabs client: {e}")
        elevenlabs_client = None
# --- End ElevenLabs Setup ---

# ... (Twilio Setup remains the same) ...
# ... (Google Auth Routes remain the same) ...
# ... (/ask route remains the same, including the call to generate_audio_base64) ...

# --- UPDATED audio generation function ---
def generate_audio_base64(text: str) -> str | None:
    """Helper function to generate audio and return it as a Base64 string."""
    if not elevenlabs_client:
        logger.warning("Cannot generate audio: ElevenLabs client not initialized.")
        return None
    try:
        logger.info(f"Generating audio for text: '{text[:30]}...'")

        # --- CORRECTED ElevenLabs API call ---
        # Use client.generate directly
        audio_bytes_iterator = elevenlabs_client.generate(
            text=text,
            voice=Voice(
                voice_id=elevenlabs_voice_id,
                settings=VoiceSettings(stability=0.7, similarity_boost=0.75)
            ),
            model="eleven_multilingual_v2"
        )
        
        # The generate function returns an iterator of chunks. We need to concatenate them.
        audio_bytes = b"".join(chunk for chunk in audio_bytes_iterator)
        # --- End Correction ---

        if not audio_bytes:
             logger.error("ElevenLabs audio generation returned empty bytes.")
             return None

        # Encode the raw audio bytes as a Base64 string
        audio_base64 = base64.b64encode(audio_bytes).decode('utf-8')
        logger.info("Audio generated and encoded successfully.")
        return audio_base64
        
    except Exception as e:
        logger.error(f"ElevenLabs audio generation failed: {e}")
        logger.exception("Detailed traceback:") # Add detailed traceback
        return None
# --- END OF UPDATED FUNCTION ---

# ... (Twilio Call Logic Routes /make_call, /handle_call, etc. remain the same) ...
# ... (Gmail Logic send_email_logic remains the same) ...
# ... (Placeholder routes /create_doc, /generate_title remain the same) ...
# ... (if __name__ == '__main__': remains the same) ...

@app.route('/incoming_call', methods=['POST'])
def handle_incoming_call():
    """Handles incoming calls via Twilio."""
    response = VoiceResponse()
    response.say("Hello, you have reached Axiom AI. How can I help you today?")
    # TODO: Add <Gather> to make this interactive
    response.hangup()
    return str(response)

# --- Twilio Call Logic Routes ---
@app.route('/make_call', methods=['POST'])
def make_call_route():
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
    
    # NEW: Generate audio for the confirmation response
    audio_base64 = generate_audio_base64(status)
    return jsonify({"status": "success", "message": status, "audio_base64": audio_base64})

def make_call_logic(phone_number, instructions):
    """Helper function that contains the logic to initiate a Twilio call."""
    if not twilio_client:
        return "Error: Twilio is not configured on the server."
        
    try:
        public_url = os.environ.get("PUBLIC_BASE_URL")
        if not public_url:
            logger.error("make_call_logic failed: PUBLIC_BASE_URL is not set.")
            return "Error: PUBLIC_BASE_URL is not set on the server."
            
        encoded_instructions = base64.urlsafe_b64encode(instructions.encode('utf-8')).decode('utf-8')
        twiml_url = f"{public_url}/handle_call?instructions={encoded_instructions}"
        
        logger.info(f"Initiating call to {phone_number} with TwiML URL: {twiml_url}")

        call = twilio_client.calls.create(
            to=phone_number,
            from_=twilio_number,
            url=twiml_url
        )
        
        logger.info(f"Call initiated with SID: {call.sid}")
        return f"Call initiated to {phone_number}." # Shorter, better for TTS
        
    except Exception as e:
        logger.error(f"Twilio call failed: {e}")
        if "is not valid" in str(e):
             return f"Error: The phone number '{phone_number}' is not valid. Please check the number and include the country code."
        return f"Error initiating call: {e}"

@app.route('/handle_call', methods=['POST'])
def handle_call():
    """Called *by Twilio* to get TwiML instructions."""
    response = VoiceResponse()
    encoded_instructions = request.args.get('instructions')
    
    if encoded_instructions:
        try:
            instructions = base64.urlsafe_b64decode(encoded_instructions).decode('utf-8')
            logger.info(f"Handling call, speaking instructions: {instructions}")
            response.say(instructions)
            # We could use ElevenLabs here, but it requires generating an MP3,
            # hosting it publicly, and using <Play> instead of <Say>.
            # We'll stick with the standard Twilio voice for calls for now.
        except Exception as e:
            logger.error(f"Error decoding instructions for call: {e}")
            response.say("Sorry, I had an error reading my instructions.")
    else:
        logger.warning("Handling call, but no instructions were provided.")
        response.say("Hello, this is Axiom AI. I was not given a message to relay.")
        
    response.hangup()
    return str(response)
# --- End Twilio Call Logic ---


# --- Placeholder for Gmail Logic ---
def send_email_logic(to, subject, body):
    gmail_service = get_google_service('gmail', 'v1')
    if not gmail_service:
        return "Error: Could not access Gmail. Please ensure Google API is authorized."
    try:
        user_profile = gmail_service.users().getProfile(userId='me').execute()
        sender_email = user_profile['emailAddress']
        if not sender_email:
             return "Error: Could not determine sender email address."
        message_body = create_message(sender_email, to, subject, body)
        message = (gmail_service.users().messages().send(userId='me', body=message_body)
                   .execute())
        logger.info(f"Message Id: {message['id']} sent successfully.")
        return f"OK, I've sent the email to {to}." # Shorter, better for TTS
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
    # ... (logic remains same)
    docs_service = get_google_service('docs', 'v1')
    if not docs_service:
        return jsonify({"error": "Google API not authorized."}), 401
    return jsonify({"status": "Document creation not implemented yet."}), 501

@app.route('/generate_title', methods=['POST'])
def generate_title():
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
        title = completion.choices[0].message.content.strip().replace("\"", "")
        logger.info(f"Generated title: {title}")
        return jsonify({"title": title})
    except Exception as e:
        logger.error(f"Title generation failed: {e}")
        return jsonify({"error": f"Failed to generate title: {e}"}), 500
# --- End Placeholder routes ---


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

