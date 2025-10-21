import os
import logging
from flask import Flask, request, jsonify
from twilio.twiml.voice_response import VoiceResponse
from openai import OpenAI

# --- Basic Configuration ---
logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

# --- OpenAI Client Initialization ---
# This is the modern, correct way to initialize the client.
# It automatically reads the OPENAI_API_KEY from your environment variables.
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

# --- Twilio Webhook for Incoming Calls ---
@app.route("/incoming_call", methods=['GET', 'POST'])
def incoming_call():
    """Handles incoming calls from Twilio."""
    response = VoiceResponse()
    response.say("Hello, you have reached Axiom. How can I help you today?", voice='alice')
    
    # Listen for the caller's response and transcribe it
    response.record(
        action="/handle_recording",
        method="POST",
        maxLength=30,
        transcribe=True,
        transcribe_callback="/handle_transcription"
    )
    
    return str(response)

# --- Placeholder route (Twilio requires an 'action' for record) ---
@app.route("/handle_recording", methods=['POST'])
def handle_recording():
    """This is a placeholder as Twilio needs an action. The main logic is in the transcription handler."""
    response = VoiceResponse()
    response.say("Processing your request.", voice='alice')
    response.hangup()
    return str(response)

# --- Handle the transcription from Twilio ---
@app.route("/handle_transcription", methods=['POST'])
def handle_transcription():
    transcription = request.form.get("TranscriptionText")
    logging.info(f"Received transcription: {transcription}")
    
    response = VoiceResponse()
    
    if transcription:
        if client:
            try:
                # Get response from OpenAI
                completion = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are Axiom, a helpful AI business assistant. Keep your responses concise and conversational for a phone call."},
                        {"role": "user", "content": transcription}
                    ]
                )
                ai_response = completion.choices[0].message.content
                logging.info(f"OpenAI response: {ai_response}")
                response.say(ai_response, voice='alice')
            except Exception as e:
                logging.error(f"OpenAI chat failed: {e}")
                response.say("I'm sorry, I'm having trouble connecting to my core intelligence. Please try again later.", voice='alice')
        else:
            response.say("My connection to OpenAI is not configured. Please check the server logs.", voice='alice')
    else:
        response.say("I'm sorry, I didn't catch that. Could you please repeat yourself?", voice='alice')
        
    response.hangup()
    return str(response)

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

if __name__ == '__main__':
    # We use Gunicorn on Render, so this part is for local testing only
    app.run(debug=True, port=5000)
