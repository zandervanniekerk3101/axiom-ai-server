import os
import logging
from flask import Flask, request, jsonify
from twilio.twiml.voice_response import VoiceResponse
import openai # Import the library to check its version

# --- Diagnostic Check ---
# This will print the installed version of the openai library to the Render logs.
logging.info(f"--- Running with OpenAI version: {openai.__version__} ---")

from openai import OpenAI

# --- Basic Configuration ---
logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

# --- OpenAI Client Initialization ---
try:
    client = OpenAI()
    logging.info("OpenAI client initialized successfully.")
except Exception as e:
    logging.error(f"Failed to initialize OpenAI client: {e}")
    client = None

# --- Main Route for Health Check ---
@app.route('/')
def index():
    return "Axiom AI Server is running."

# --- Endpoint for the Android App ---
@app.route('/ask', methods=['POST'])
def ask_axiom():
    """Handles questions from the Android app."""
    data = request.get_json()
    if not data or 'prompt' not in data:
        return jsonify({'error': 'Invalid request. "prompt" is required.'}), 400

    prompt = data['prompt']
    logging.info(f"Received prompt from app: {prompt}")

    if not client:
        return jsonify({'error': 'OpenAI client is not initialized on the server.'}), 500

    try:
        # Get response from OpenAI
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are Axiom, a helpful business assistant."},
                {"role": "user", "content": prompt}
            ]
        )
        response_text = completion.choices[0].message.content
        logging.info(f"OpenAI response: {response_text}")
        return jsonify({'response': response_text})

    except Exception as e:
        logging.error(f"OpenAI chat failed: {e}", exc_info=True)
        return jsonify({'error': 'Failed to get response from OpenAI'}), 500

# --- Twilio Routes (for phone calls - not relevant to the current app issue) ---
@app.route("/incoming_call", methods=['POST'])
def incoming_call():
    """Handles incoming calls and starts transcription."""
    response = VoiceResponse()
    response.say("Hello, you've reached Axiom. Please state your query after the beep.")
    response.record(
        transcribe=True,
        transcribe_callback=f"{os.getenv('PUBLIC_BASE_URL')}/handle_transcription",
        play_beep=True
    )
    return str(response)

@app.route("/handle_transcription", methods=['POST'])
def handle_transcription():
    """Receives the transcription and gets a response from OpenAI."""
    transcription_text = request.form['TranscriptionText']
    logging.info(f"Transcription received: {transcription_text}")

    response = VoiceResponse()
    try:
        if not client:
            raise Exception("OpenAI client not initialized")
        
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are Axiom, a helpful business assistant speaking over the phone."},
                {"role": "user", "content": transcription_text}
            ]
        )
        ai_response = completion.choices[0].message.content
        logging.info(f"OpenAI response for call: {ai_response}")
        response.say(ai_response)
    except Exception as e:
        logging.error(f"Error during call handling: {e}")
        response.say("Sorry, I encountered an error. Please try again later.")
    
    response.hangup()
    return str(response)

if __name__ == '__main__':
    app.run(debug=True)

