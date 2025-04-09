# serpent_cipher.py
from ciphers.serpent import _serpent
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_serpent_key(bits=128):
    if bits not in [128, 192, 256]:
        raise ValueError("Długość klucza Serpent musi wynosić 128, 192 lub 256 bitów.")
    return get_random_bytes(bits // 8)

def encrypt_serpent_ecb(plaintext: str, key: bytes) -> bytes:
    ctx = _serpent(key)
    padded = pad(plaintext.encode(), 16)
    ciphertext = b""
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        ciphertext += ctx.encrypt(block)
    return ciphertext

def decrypt_serpent_ecb(ciphertext: bytes, key: bytes) -> str:
    ctx = _serpent(key)
    plaintext = b""
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        plaintext += ctx.decrypt(block)
    return unpad(plaintext, 16).decode()
