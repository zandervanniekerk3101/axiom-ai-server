# ... (other imports) ...
from googleapiclient.errors import HttpError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
logger.info("✅ Flask app object created.") # <-- ADD THIS LINE
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret_key_replace_me")

# ... (Google API Setup remains the same) ...
# ... (Gmail Helper remains the same) ...
# ... (OpenAI Setup remains the same) ...
# ... (ElevenLabs Setup remains the same) ...
# ... (Twilio Setup remains the same) ...


logger.info("🏁 Registering Flask routes...") # <-- ADD THIS LINE
@app.route('/')
def home():
    auth_status = "Google API Authorized" if google_creds and google_creds.valid else "Google API NOT Authorized (Visit /authorize_google)"
    return f"Axiom AI Server is running.<br>{auth_status}"

# ... (Rest of the routes /authorize_google, /oauth2callback, /ask, etc. remain the same) ...

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

# ... (rest of the code remains the same) ...

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

