import secrets
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from sympy import isprime


class DiffieHellman:
    def __init__(self, p, g):
        if not isprime(p):
            raise ValueError("p musi być liczbą pierwszą.")
        if not (1 < g < p):
            raise ValueError("g musi być większe niż 1 i mniejsze niż p.")
        if p <= 2:
            raise ValueError("p musi być liczbą pierwszą większą niż 2.")
        
        self.p = p
        self.g = g
        self.private_key = secrets.randbelow(self.p - 2) + 1  # Klucz prywatny: 1 <= private_key < p - 1
        self.public_key = pow(self.g, self.private_key, self.p)  # Klucz publiczny
    
    def compute_shared_secret(self, other_public_key):
        if not (1 <= other_public_key < self.p):
            raise ValueError("Klucz publiczny drugiej strony jest niepoprawny.")
        return pow(other_public_key, self.private_key, self.p)
    
    @staticmethod
    def derive_key(shared_secret):
        # Wyprowadzenie klucza AES z sekretu przy użyciu SHA-256
        return sha256(str(shared_secret).encode()).digest()

    @staticmethod
    def encrypt_message(message, key):
        if not isinstance(message, str):
            raise ValueError("Wiadomość musi być ciągiem tekstowym.")
        if len(key) != 32:  # Klucz AES musi być 256-bitowy
            raise ValueError("Klucz AES musi mieć długość 32 bajty.")
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    @staticmethod
    def decrypt_message(encrypted_message, key):
        if len(key) != 32:  # Klucz AES musi być 256-bitowy
            raise ValueError("Klucz AES musi mieć długość 32 bajty.")
        data = base64.b64decode(encrypted_message)
        iv = data[:AES.block_size]
        ciphertext = data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode('utf-8')
