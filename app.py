import os
import logging
import sys
import openai # Import openai here to check version

# --- FORCE-PROOF DIAGNOSTIC ---
# This will print to the logs the moment the server starts.
# If you don't see these lines, Render is NOT running this code.
print("🔥 Axiom AI server starting with Python version:", sys.version)
print("🔥 Detected OpenAI version:", openai.__version__)
# --- END DIAGNOSTIC ---

from flask import Flask, request, jsonify
from twilio.twiml.voice_response import VoiceResponse
from openai import OpenAI

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

try:
    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    logging.info("OpenAI client initialized successfully.")
except Exception as e:
    logging.error(f"Failed to initialize OpenAI client: {e}")
    client = None

@app.route('/')
def index():
    return "Axiom AI Server is running."

@app.route('/ask', methods=['POST'])
def ask_axiom():
    data = request.get_json()
    if not data or 'prompt' not in data:
        return jsonify({'error': 'Invalid request. "prompt" is required.'}), 400

    prompt = data['prompt']
    logging.info(f"Received prompt from app: {prompt}")

    if not client:
        return jsonify({'error': 'OpenAI client is not initialized on the server.'}), 500

    try:
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

# Twilio routes remain the same...
@app.route("/incoming_call", methods=['POST'])
def incoming_call():
    response = VoiceResponse()
    response.say("Hello, you've reached Axiom. Please state your query after the beep.")
    public_base_url = os.getenv('PUBLIC_BASE_URL')
    transcribe_callback_url = f"{public_base_url}/handle_transcription"
    response.record(
        transcribe=True,
        transcribe_callback=transcribe_callback_url,
        play_beep=True
    )
    return str(response)

@app.route("/handle_transcription", methods=['POST'])
def handle_transcription():
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

