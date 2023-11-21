from hashlib import sha256
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from string import printable


def get_shared_key(public_key: int, private_key: int, modulus: int) -> int:
    shared_key = pow(public_key, private_key, modulus)
    return shared_key


def get_public_key(generator: int, private_key: int, modulus: int) -> int:
    public_key = pow(generator, private_key, modulus)
    return public_key


def encrypt(key: int, message: bytes) -> bytes:
    key = sha256(long_to_bytes(key)).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_message = cipher.encrypt(pad(message, 16))
    return encrypted_message


def decrypt(key: int, message: bytes) -> bytes:
    key = sha256(long_to_bytes(key)).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_message = unpad(cipher.decrypt(message), 16)
    for i in decrypted_message:
        if chr(i) not in printable:
            raise Exception('Invalid message while decrypting')
    return decrypted_message
