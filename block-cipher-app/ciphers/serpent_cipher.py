# serpent_cipher.py
from ciphers.serpent import _serpent
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_serpent_key(bits=128):
    if bits not in [128, 192, 256]:
        raise ValueError("Długość klucza Serpent musi wynosić 128, 192 lub 256 bitów.")
    return get_random_bytes(bits // 8)

def encrypt_serpent_ecb(plaintext: str, key: bytes, use_padding=True) -> bytes:
    ctx = _serpent(key)
    padded = plaintext.encode()
    if use_padding:
        padded = pad(padded, 16)
    elif len(padded) % 16 != 0:
        raise ValueError("Długość danych musi być wielokrotnością 16 bajtów, gdy padding jest wyłączony.")

    ciphertext = b""
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        ciphertext += ctx.encrypt(block)
    return ciphertext

def decrypt_serpent_ecb(ciphertext: bytes, key: bytes, use_padding=True) -> str:
    ctx = _serpent(key)
    plaintext = b""
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        plaintext += ctx.decrypt(block)
    if use_padding:
        plaintext = unpad(plaintext, 16)
    return plaintext.decode()
