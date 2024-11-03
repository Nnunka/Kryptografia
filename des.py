import base64
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

class DESCipher:
    def __init__(self, key):
        if len(key) != 8:
            raise ValueError("Klucz DES musi mieć dokładnie 8 bajtów.")
        self.key = key

    def encrypt_block_mode(self, plaintext):
        cipher = DES.new(self.key, DES.MODE_CBC)
        iv = cipher.iv
        padded_data = pad(plaintext.encode(), DES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        encrypted_data = iv + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')

    def decrypt_block_mode(self, b64_ciphertext):
        ciphertext = base64.b64decode(b64_ciphertext)
        iv = ciphertext[:DES.block_size]
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext[DES.block_size:]), DES.block_size)
        return decrypted_data.decode()

    def encrypt_stream_mode(self, plaintext):
        cipher = DES.new(self.key, DES.MODE_CFB)
        iv = cipher.iv
        ciphertext = cipher.encrypt(plaintext.encode())
        encrypted_data = iv + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')

    def decrypt_stream_mode(self, b64_ciphertext):
        ciphertext = base64.b64decode(b64_ciphertext)
        iv = ciphertext[:DES.block_size]
        cipher = DES.new(self.key, DES.MODE_CFB, iv)
        decrypted_data = cipher.decrypt(ciphertext[DES.block_size:])
        return decrypted_data.decode()
