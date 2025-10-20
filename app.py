import os
import logging
from flask import Flask, request, jsonify, Response
from twilio.rest import Client as TwilioClient
from twilio.twiml.voice_response import VoiceResponse, Gather
from dotenv import load_dotenv
import openai
from collections import defaultdict

# ---------- 1. Setup and Configuration ----------
load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("axiom")

# Load credentials from environment variables
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN  = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_NUMBER      = os.getenv("TWILIO_NUMBER")
PUBLIC_BASE_URL    = os.getenv("PUBLIC_BASE_URL")
OPENAI_API_KEY     = os.getenv("OPENAI_API_KEY")
openai.api_key     = OPENAI_API_KEY

# Validate that all necessary keys are present
if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_NUMBER, PUBLIC_BASE_URL, OPENAI_API_KEY]):
    logger.critical("CRITICAL ERROR: Not all environment variables are set. The application cannot start.")

# Initialize the Twilio client
twilio = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# In-memory conversation state (for simplicity)
SESSION = defaultdict(lambda: {"history": []})

app = Flask(__name__)

# ---------- 2. Core AI and Helper Functions ----------
def ai_reply(call_sid, user_text):
    """Gets a response from OpenAI based on the conversation history."""
    state = SESSION[call_sid]
    state["history"].append({"role": "user", "content": user_text})

    system_prompt = (
        "You are Axiom AI, an advanced conversational phone agent. Your goal is to be helpful, "
        "natural, and concise. Keep your responses short and conversational, suitable for a phone call."
    )
    messages = [{"role": "system", "content": system_prompt}] + state["history"]

    try:
        resp = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages
        )
        text = resp.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"OpenAI API error for CallSid {call_sid}: {e}", exc_info=True)
        text = "I'm sorry, I'm having a little trouble connecting to my thoughts right now. Could you say that again?"

    state["history"].append({"role": "assistant", "content": text})
    return text

# ---------- 3. Web Server Routes (Endpoints) ----------

@app.route("/")
def home():
    """Homepage to confirm the server is online."""
    return "Axiom AI Server is Online!"

@app.route("/health")
def health():
    """Health check endpoint for keep-alive services."""
    return "OK", 200

# --- INBOUND PHONE CALL LOGIC ---
@app.route("/incoming_call", methods=["POST"])
def incoming_call():
    """Handles new incoming calls from Twilio."""
    call_sid = request.form.get("CallSid")
    logger.info(f"New incoming call received: SID {call_sid}")
    
    greeting = "Hello, you've reached Axiom. How can I help you today?"
    SESSION[call_sid]["history"] = [{"role": "assistant", "content": greeting}]

    vr = VoiceResponse()
    vr.say(greeting, voice="alice")

    gather = Gather(
        input="speech",
        speechTimeout="auto",
        action="/process_speech",
        method="POST"
    )
    vr.append(gather)
    return Response(str(vr), mimetype="text/xml")

@app.route("/process_speech", methods=["POST"])
def process_speech():
    """Processes the speech from the caller and continues the conversation."""
    call_sid = request.form.get("CallSid")
    speech_result = request.form.get("SpeechResult", "")
    logger.info(f"Call SID {call_sid} - User said: '{speech_result}'")

    ai_response = ai_reply(call_sid, speech_result)
    logger.info(f"Call SID {call_sid} - AI responded: '{ai_response}'")

    vr = VoiceResponse()
    vr.say(ai_response, voice="alice")
    
    gather = Gather(
        input="speech",
        speechTimeout="auto",
        action="/process_speech",
        method="POST"
    )
    vr.append(gather)
    return Response(str(vr), mimetype="text/xml")

# --- ANDROID APP LOGIC ---
@app.route("/ask", methods=["POST"])
def ask_axiom():
    """Handles text-based queries from the Android app."""
    data = request.get_json(force=True)
    user_prompt = data.get("prompt", "")
    try:
        completion = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are Axiom AI, a helpful business assistant."},
                {"role": "user", "content": user_prompt}
            ]
        )
        ai_response = completion.choices[0].message.content
        return jsonify({"response": ai_response})
    except Exception as e:
        logger.error(f"OpenAI chat failed: {e}", exc_info=True)
        return jsonify({"error": "AI error"}), 500

# ---------- 4. Main Execution Block ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)

