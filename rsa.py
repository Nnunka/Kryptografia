from Crypto.Util.number import getPrime, inverse, GCD


class RSACipher:
    def __init__(self, bit_length=2048):
        self.bit_length = bit_length
        self.public_key = None
        self.private_key = None
        self.n = None
        self.generate_keys()

    def generate_keys(self):
        p = getPrime(self.bit_length // 2)
        q = getPrime(self.bit_length // 2)
        self.n = p * q
        phi_n = (p - 1) * (q - 1)
        e = 65537
        if GCD(e, phi_n) != 1:
            raise ValueError("e i phi(n) nie są względnie pierwsze.")
        d = inverse(e, phi_n)
        self.public_key = (self.n, e)
        self.private_key = (self.n, d)

    def encrypt(self, plaintext):
        n, e = self.public_key
        plaintext_bytes = plaintext.encode('utf-8')
        max_block_size = (self.n.bit_length() // 8) - 1
        ciphertext = []
        for i in range(0, len(plaintext_bytes), max_block_size):
            block = plaintext_bytes[i:i + max_block_size]
            block_int = int.from_bytes(block, byteorder='big')
            if block_int >= n:
                raise ValueError("Blok jest za duży dla klucza RSA.")
            encrypted_block = pow(block_int, e, n)
            ciphertext.append(encrypted_block)
        return ciphertext

    def decrypt(self, ciphertext):
        n, d = self.private_key
        plaintext_bytes = bytearray()
        for block in ciphertext:
            decrypted_block = pow(block, d, n)
            block_bytes = decrypted_block.to_bytes((decrypted_block.bit_length() + 7) // 8, byteorder='big')
            plaintext_bytes.extend(block_bytes)
        return plaintext_bytes.decode('utf-8')
