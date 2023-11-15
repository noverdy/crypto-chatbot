from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
from Crypto.Util.number import getPrime
from utils.dhke import get_shared_key, encrypt, decrypt, calculate_public_key as calculate_pk
from utils.message import get_response
from dotenv import load_dotenv
import json
import os


load_dotenv()
app = Flask(__name__)
CORS(app)
PRIVATE_KEY = int(os.environ['PRIVATE_KEY'], 16)
MODULUS = int(os.environ['MODULUS'], 16)


@app.route('/generate-key', methods=['GET'])
def generate_key():
    key = getPrime(2048)
    return jsonify({
        'key': hex(key),
        'modulus': hex(MODULUS)
    })


@app.route('/calculate-public-key', methods=['POST'])
def calculate_public_key():
    try:
        data = json.loads(request.data)
        key = int(data['private_key'], 16)
        modulus = int(data['modulus'], 16)
        public_key = calculate_pk(key, modulus)
        return jsonify({
            'public_key': hex(public_key),
            'modulus': hex(modulus)
        })
    except Exception as e:
        return jsonify({'error': getattr(e, 'message', str(e))}), 400


@app.route('/exchange', methods=['POST'])
def exchange():
    try:
        data = json.loads(request.data)
        public_key = int(data['public_key'], 16)
        shared_key = get_shared_key(PRIVATE_KEY, public_key, MODULUS)
        return jsonify({
            'shared_key': hex(shared_key),
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
