# twofish_cipher.py
from twofish import Twofish # Import biblioteki Twofish
from Crypto.Random import get_random_bytes # Generowanie klucza
from Crypto.Util.Padding import pad, unpad # Padding

# Generowanie klucza do Twofish
def generate_twofish_key(bits=128):
    if bits not in [128, 192, 256]:
        raise ValueError("Długość klucza Twofish musi wynosić 128, 192 lub 256 bitów.")
    return get_random_bytes(bits // 8) # Podział przez 8, bo bits → bajty

# Funkcja szyfrująca dane za pomocą Twofish ECB
def encrypt_twofish_ecb(plaintext: str, key: bytes, use_padding=True) -> bytes:
    tf = Twofish(key) # Utworzenie obiektu szyfrującego
    padded = plaintext.encode()
    if use_padding:
        padded = pad(padded, 16) # Padding danych (Twofish operuje na blokach 16 bajtów)
    elif len(padded) % 16 != 0:
        raise ValueError("Długość danych musi być wielokrotnością 16 bajtów, gdy padding jest wyłączony.")

    ciphertext = b"" # Bufor: pusta zmienna bajtowa, która zbierze zaszyfrowane bloki
    # Pętla szyfrująca każdy blok
    for i in range(0, len(padded), 16):  # Przechodzimy po danych co 16 bajtów
        block = padded[i:i+16] # Wyciągamy jeden blok
        ciphertext += tf.encrypt(block) # Szyfrujemy go i dodajemy do ciphertext
    return ciphertext

# Funkcja deszyfrująca dane zaszyfrowane Twofishem
def decrypt_twofish_ecb(ciphertext: bytes, key: bytes, use_padding=True) -> str:
    tf = Twofish(key) # Obiekt deszyfrujący
    plaintext = b"" # Bufor na odszyfrowany tekst
    # Deszyfrowanie bloków po kolei
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16] # Pobieramy blok zaszyfrowany
        plaintext += tf.decrypt(block) # Odszyfrowujemy i dodajemy do bufora
    if use_padding:
        plaintext = unpad(plaintext, 16) # Usuwamy padding, jeśli był użyty
    return plaintext.decode() # Bajty na string
