import json
import os

from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.number import getPrime, long_to_bytes
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from openai import OpenAI

from utils.aes import decrypt, encrypt
from utils.dhke import get_public_key, get_shared_key
from utils.message import get_response

load_dotenv()
app = Flask(__name__)
CORS(app)

ai = OpenAI()

GENERATOR = int(os.environ['GENERATOR'], 16)
MODULUS = int(os.environ['MODULUS'], 16)
PRIVATE_KEY = int(os.environ['PRIVATE_KEY'], 16)

PUBLIC_KEY = get_public_key(GENERATOR, PRIVATE_KEY, MODULUS)
DERIVED_KEYS = {}


@app.route('/parameters', methods=['GET'])
def parameters():
    return jsonify({
        'generator': hex(GENERATOR),
        'modulus': hex(MODULUS)
    })


@app.route('/key-exchange', methods=['POST'])
def exchange():
    global DERIVED_KEYS
    try:
        data = json.loads(request.data)
        client_public_key = int(data['public_key'], 16)
        client_private_key = int(data['private_key'], 16)

        shared_key = get_shared_key(client_public_key, PRIVATE_KEY, MODULUS)
        derived_key = PBKDF2(long_to_bytes(shared_key), b'',
                             16, 100000, hmac_hash_module=SHA512)
        DERIVED_KEYS[data['public_key']] = derived_key

        return jsonify({
            'public_key': hex(PUBLIC_KEY),
            'modulus': hex(MODULUS)
        })
    except Exception as e:
        raise e
        return jsonify({'error': getattr(e, 'message', str(e))}), 400


@app.route('/respond', methods=['POST'])
def respond():
    try:
        data = json.loads(request.data)
        public_key = data['public_key']
        message = data['message']

        derived_key = DERIVED_KEYS[public_key]
        decrypted_message = decrypt(bytes.fromhex(message), derived_key)

        response = get_response(ai, decrypted_message)
        encrypted_response = encrypt(response, derived_key)

        return jsonify({
            'response': encrypted_response.hex(),
            'public_key': hex(PUBLIC_KEY),
        })
    except Exception as e:
        return jsonify({'error': getattr(e, 'message', str(e))}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
