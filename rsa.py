from Crypto.Util.number import inverse, GCD

class RSACipher:
    def __init__(self, p, q):
        """
        Inicjalizacja na podstawie podanych liczb pierwszych p i q.
        """
        if p == q:
            raise ValueError("Liczby p i q muszą być różne.")
        if not self.is_prime(p) or not self.is_prime(q):
            raise ValueError("Obie liczby muszą być liczbami pierwszymi.")

        self.n = p * q
        phi_n = (p - 1) * (q - 1)
        self.e = 65537  # Typowy wykładnik publiczny
        if GCD(self.e, phi_n) != 1:
            raise ValueError("e i phi(n) nie są względnie pierwsze.")
        self.d = inverse(self.e, phi_n)
        self.public_key = (self.n, self.e)
        self.private_key = (self.n, self.d)

    @staticmethod
    def is_prime(num):
        """Prosta funkcja sprawdzająca, czy liczba jest pierwsza."""
        if num < 2:
            return False
        for i in range(2, int(num**0.5) + 1):
            if num % i == 0:
                return False
        return True

    def encrypt(self, plaintext):
        """Szyfruje tekst za pomocą klucza publicznego."""
        n, e = self.public_key
        plaintext_bytes = plaintext.encode('utf-8')
        max_block_size = max((self.n.bit_length() // 8) - 1, 1)  # Zapewnia, że krok w range() nie będzie zerem
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
        """Odszyfrowuje tekst za pomocą klucza prywatnego."""
        n, d = self.private_key
        plaintext_bytes = bytearray()
        for block in ciphertext:
            decrypted_block = pow(block, d, n)
            block_bytes = decrypted_block.to_bytes((decrypted_block.bit_length() + 7) // 8, byteorder='big')
            plaintext_bytes.extend(block_bytes)
        return plaintext_bytes.decode('utf-8')
