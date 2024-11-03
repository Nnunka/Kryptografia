import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class AESCipher:
    def __init__(self, key):
        if len(key) not in [16, 24, 32]:
            raise ValueError("Klucz AES musi mieć 16, 24 lub 32 bajty.")
        self.key = key

    def encrypt_block_mode(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CBC)
        iv = cipher.iv
        padded_data = pad(plaintext.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        encrypted_data = iv + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')

    def decrypt_block_mode(self, b64_ciphertext):
        ciphertext = base64.b64decode(b64_ciphertext)
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
        return decrypted_data.decode()

    def encrypt_stream_mode(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CFB)
        iv = cipher.iv
        ciphertext = cipher.encrypt(plaintext.encode())
        encrypted_data = iv + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')

    def decrypt_stream_mode(self, b64_ciphertext):
        ciphertext = base64.b64decode(b64_ciphertext)
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        decrypted_data = cipher.decrypt(ciphertext[AES.block_size:])
        return decrypted_data.decode()
