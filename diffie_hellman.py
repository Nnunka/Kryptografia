import secrets
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

class DiffieHellman:
    def __init__(self, p=None, g=None):
        # Domyślne wartości p i g (testowe)
        self.p = p or 23  # Duża liczba pierwsza (w praktyce powinna być większa)
        self.g = g or 5   # Generator
        self.private_key = secrets.randbelow(self.p)  # Klucz prywatny
        self.public_key = pow(self.g, self.private_key, self.p)  # Klucz publiczny
    
    def compute_shared_secret(self, other_public_key):
        return pow(other_public_key, self.private_key, self.p)
    
    def derive_key(shared_secret):
        # Wyprowadzenie klucza AES z sekretu przy użyciu SHA-256
        return sha256(str(shared_secret).encode()).digest()

    def encrypt_message(message, key):
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    def decrypt_message(encrypted_message, key):
        data = base64.b64decode(encrypted_message)
        iv = data[:AES.block_size]
        ciphertext = data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode('utf-8')
