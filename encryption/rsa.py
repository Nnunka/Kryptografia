from Crypto.Util.number import getPrime, inverse, GCD


class RSACipher:
    """
    Implementacja algorytmu RSA z automatycznym generowaniem kluczy.
    
    Algorytm opiera się na dwóch dużych liczbach pierwszych (p, q) do generowania kluczy.
    Obsługuje szyfrowanie i odszyfrowywanie tekstu przy użyciu klucza publicznego i prywatnego.
    """

    def __init__(self, bit_length=2048):
        """
        Inicjalizuje obiekt RSACipher z określoną długością klucza.

        Args:
            bit_length (int): Długość klucza w bitach (domyślnie 2048).
        """
        self.bit_length = bit_length
        self.public_key = None
        self.private_key = None
        self.n = None
        self.generate_keys()

    def generate_keys(self):
        """
        Generuje klucze publiczny i prywatny RSA.

        Procedura:
        - Losowanie dwóch dużych liczb pierwszych p i q.
        - Obliczenie n = p * q (moduł RSA).
        - Obliczenie phi(n) = (p - 1) * (q - 1) (funkcja Eulera).
        - Wybranie wykładnika publicznego e (zwykle 65537).
        - Obliczenie odwrotności modularnej e względem phi(n) jako klucz prywatny d.

        Raises:
            ValueError: Jeśli e i phi(n) nie są względnie pierwsze.
        """
        # Losowanie liczb pierwszych p i q
        p = getPrime(self.bit_length // 2)
        q = getPrime(self.bit_length // 2)
        
        # Obliczenie modułu n i phi(n)
        self.n = p * q
        phi_n = (p - 1) * (q - 1)
        
        # Wybór typowego wykładnika publicznego e
        e = 65537
        if GCD(e, phi_n) != 1:
            raise ValueError("e i phi(n) nie są względnie pierwsze.")
        
        # Obliczenie odwrotności modularnej d
        d = inverse(e, phi_n)
        
        # Ustawienie kluczy publicznego i prywatnego
        self.public_key = (self.n, e)
        self.private_key = (self.n, d)

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
        """
        Odszyfrowuje tekst zaszyfrowany za pomocą klucza prywatnego.

        Zaszyfrowane bloki są odszyfrowywane pojedynczo i łączone w pełny tekst.

        Args:
            ciphertext (list[int]): Lista liczb całkowitych reprezentujących zaszyfrowane bloki.

        Returns:
            str: Odszyfrowany tekst.

        Raises:
            ValueError: Jeśli dane nie mogą zostać odszyfrowane.
        """
        n, d = self.private_key
        plaintext_bytes = bytearray()

        # Odszyfrowywanie każdego bloku
        for block in ciphertext:
            decrypted_block = pow(block, d, n)
            block_bytes = decrypted_block.to_bytes((decrypted_block.bit_length() + 7) // 8, byteorder='big')
            plaintext_bytes.extend(block_bytes)

        return plaintext_bytes.decode('utf-8')
