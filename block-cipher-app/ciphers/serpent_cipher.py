# serpent_cipher.py
from ciphers.serpent import _serpent  # Implementacja szyfru Serpent poprzez plik
from Crypto.Random import get_random_bytes  # Losowy klucz
from Crypto.Util.Padding import pad, unpad # Padding danych

# Generowanie klucza do Serpent o długości 128, 192 lub 256 bitów
def generate_serpent_key(bits=128):
    if bits not in [128, 192, 256]:
        raise ValueError("Długość klucza Serpent musi wynosić 128, 192 lub 256 bitów.")
    return get_random_bytes(bits // 8) # Podział przez 8, bo bits → bajty

# Szyfrowanie tekstu jawnego algorytmem Serpent w trybie ECB
def encrypt_serpent_ecb(plaintext: str, key: bytes, use_padding=True) -> bytes:
    ctx = _serpent(key) # Tworzenie obiektu szyfrującego
    padded = plaintext.encode() # Zamiana tekstu na bajty
    if use_padding:
        padded = pad(padded, 16) # Padding danych (Serpent używa bloków 16 bajtów)
    elif len(padded) % 16 != 0:
        raise ValueError("Długość danych musi być wielokrotnością 16 bajtów, gdy padding jest wyłączony.")

    ciphertext = b"" # Tworzymy pusty ciąg bajtów, do którego będziemy doklejać zaszyfrowane bloki
    #  Pętla szyfrująca każdy 16-bajtowy blok tekstu
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]  # Wydzielamy blok 16 bajtów (ECB nie szyfruje całego ciągu naraz)
        ciphertext += ctx.encrypt(block)  # Szyfrujemy blok i dodajemy do końcowego ciphertext
    return ciphertext

# Deszyfrowanie danych Serpent w trybie ECB
def decrypt_serpent_ecb(ciphertext: bytes, key: bytes, use_padding=True) -> str:
    ctx = _serpent(key) # Obiekt do deszyfrowania
    plaintext = b"" # Inicjalizujemy pusty bajtowy string, do którego będziemy doklejać rozszyfrowane bloki
    # Deszyfrowanie bloków po 16 bajtów
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16] # Pobieramy 16 bajtów zaszyfrowanego tekstu
        plaintext += ctx.decrypt(block) # Deszyfrujemy blok i dodajemy do końcowego plaintext
    if use_padding:
        plaintext = unpad(plaintext, 16) # Usunięcie paddingu
    return plaintext.decode()# Zamiana bajtów na tekst
