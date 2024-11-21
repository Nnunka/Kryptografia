from Crypto.Util.number import inverse, GCD

class RSACipher:
    """
    Implementacja algorytmu RSA do szyfrowania i deszyfrowania danych.

    Algorytm działa na podstawie dwóch dużych liczb pierwszych (p, q), które
    służą do generowania kluczy publicznych i prywatnych. 
    """

    def __init__(self, p, q):
        """
        Inicjalizuje obiekt RSACipher na podstawie podanych liczb pierwszych p i q.

        Args:
            p (int): Liczba pierwsza.
            q (int): Liczba pierwsza różna od p.

        Raises:
            ValueError: Jeśli liczby p i q nie są liczbami pierwszymi, są takie same
                        lub jeśli wykładnik publiczny e nie jest względnie pierwszy z phi(n).
        """
        if p == q:
            raise ValueError("Liczby p i q muszą być różne.")
        if not self.is_prime(p) or not self.is_prime(q):
            raise ValueError("Obie liczby muszą być liczbami pierwszymi.")

        # Obliczenie modułu RSA (n) i funkcji Eulera (phi_n)
        self.n = p * q
        phi_n = (p - 1) * (q - 1)

        # Wykładnik publiczny (typowo 65537)
        self.e = 65537
        if GCD(self.e, phi_n) != 1:
            raise ValueError("e i phi(n) nie są względnie pierwsze.")

        # Obliczenie wykładnika prywatnego (d)
        self.d = inverse(self.e, phi_n)

        # Zapisanie klucza publicznego i prywatnego
        self.public_key = (self.n, self.e)
        self.private_key = (self.n, self.d)

    @staticmethod
    def is_prime(num):
        """
        Prosta funkcja sprawdzająca, czy liczba jest pierwsza.

        Args:
            num (int): Liczba do sprawdzenia.

        Returns:
            bool: True, jeśli liczba jest pierwsza, False w przeciwnym razie.
        """
        if num < 2:
            return False
        for i in range(2, int(num**0.5) + 1):
            if num % i == 0:
                return False
        return True

    def encrypt(self, plaintext):
        """
        Szyfruje tekst za pomocą klucza publicznego.

        Tekst jest dzielony na bloki, które mieszczą się w modulo n.
        Każdy blok jest szyfrowany oddzielnie.

        Args:
            plaintext (str): Tekst do zaszyfrowania.

        Returns:
            list[int]: Lista liczb całkowitych reprezentujących zaszyfrowane bloki.

        Raises:
            ValueError: Jeśli blok danych jest większy niż klucz RSA.
        """
        n, e = self.public_key
        plaintext_bytes = plaintext.encode('utf-8')

        # Maksymalny rozmiar bloku (w bajtach), uwzględniając ograniczenie RSA
        max_block_size = max((self.n.bit_length() // 8) - 1, 1)
        ciphertext = []

        # Szyfrowanie każdego bloku
        for i in range(0, len(plaintext_bytes), max_block_size):
            block = plaintext_bytes[i:i + max_block_size]
            block_int = int.from_bytes(block, byteorder='big')
            if block_int >= n:
                raise ValueError("Blok jest za duży dla klucza RSA.")
            encrypted_block = pow(block_int, e, n)
            ciphertext.append(encrypted_block)

        return ciphertext

    def decrypt(self, ciphertext):
        """
        Odszyfrowuje tekst za pomocą klucza prywatnego.

        Zaszyfrowane bloki są odszyfrowywane pojedynczo i łączone w pełny tekst.

        Args:
            ciphertext (list[int]): Lista liczb całkowitych reprezentujących zaszyfrowane bloki.

        Returns:
            str: Odszyfrowany tekst.

        Raises:
            ValueError: Jeśli dane nie są poprawnie odszyfrowane.
        """
        n, d = self.private_key
        plaintext_bytes = bytearray()

        # Deszyfrowanie każdego bloku
        for block in ciphertext:
            decrypted_block = pow(block, d, n)
            block_bytes = decrypted_block.to_bytes((decrypted_block.bit_length() + 7) // 8, byteorder='big')
            plaintext_bytes.extend(block_bytes)

        return plaintext_bytes.decode('utf-8')
