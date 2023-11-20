import json
import os

from Crypto.Util.number import getPrime
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

from utils.dhke import get_public_key, get_shared_key
from utils.message import get_response

GENERATOR = int(os.environ['GENERATOR'], 16)
MODULUS = int(os.environ['MODULUS'], 16)
PRIVATE_KEY = int(os.environ['PRIVATE_KEY'], 16)

PUBLIC_KEY = get_public_key(GENERATOR, PRIVATE_KEY, MODULUS)
SHARED_KEYS = {}


load_dotenv()
app = Flask(__name__)
CORS(app)


@app.route('/parameters', methods=['GET'])
def parameters():
    return jsonify({
        'generator': hex(GENERATOR),
        'modulus': hex(MODULUS)
    })


@app.route('/key-exchange', methods=['POST'])
def exchange():
    global SHARED_KEYS
    try:
        data = json.loads(request.data)
        client_public_key = int(data['public_key'], 16)
        shared_key = get_shared_key(client_public_key, PRIVATE_KEY, MODULUS)
        SHARED_KEYS[client_public_key] = shared_key
        return jsonify({
            'public_key': hex(PUBLIC_KEY),
            'modulus': hex(MODULUS)
        })
    except Exception as e:
        return jsonify({'error': getattr(e, 'message', str(e))}), 400


@app.route('/respond', methods=['POST'])
def respond():
    try:
        data = json.loads(request.data)
        public_key = int(data['public_key'], 16)
        message = data['message']

        shared_key = get_shared_key(PRIVATE_KEY, public_key, MODULUS)
        decrypted_message = decrypt(shared_key, bytes.fromhex(message))
        response = get_response(decrypted_message)
        encrypted_response = encrypt(shared_key, response)
        return jsonify({'response': encrypted_response.hex()})
    except Exception as e:
        return jsonify({'error': getattr(e, 'message', str(e))}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
