from flask import Flask, jsonify, request, render_template
from Crypto.Util.number import getPrime
from utils.dhke import get_shared_key, encrypt, decrypt
from utils.message import get_response
from dotenv import load_dotenv
import json
import os


load_dotenv()
app = Flask(__name__)
PRIVATE_KEY = int(os.environ['PRIVATE_KEY'], 16)
MODULUS = int(os.environ['MODULUS'], 16)


@app.route('/generate-key', methods=['GET'])
def generate_key():
    key = getPrime(2048)
    return jsonify({
        'key': hex(key),
        'modulus': hex(MODULUS)
    })


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
    app.run(debug=True)
