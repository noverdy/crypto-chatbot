import json
import random


def get_response(message: bytes) -> bytes:
    with open('assets/responses.json') as f:
        responses_json = f.read()
    responses = json.loads(responses_json)
    response = random.choice(responses)
    return response.encode()
