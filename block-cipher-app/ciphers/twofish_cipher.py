# twofish_cipher.py
from twofish import Twofish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_twofish_key(bits=128):
    if bits not in [128, 192, 256]:
        raise ValueError("Długość klucza Twofish musi wynosić 128, 192 lub 256 bitów.")
    return get_random_bytes(bits // 8)

def encrypt_twofish_ecb(plaintext: str, key: bytes) -> bytes:
    tf = Twofish(key)
    padded = pad(plaintext.encode(), 16)
    ciphertext = b""
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        ciphertext += tf.encrypt(block)
    return ciphertext

def decrypt_twofish_ecb(ciphertext: bytes, key: bytes) -> str:
    tf = Twofish(key)
    plaintext = b""
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        plaintext += tf.decrypt(block)
    return unpad(plaintext, 16).decode()
