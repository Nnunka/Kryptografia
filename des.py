import base64
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

class DESCipher:
    """
    Klasa do obsługi szyfrowania i deszyfrowania danych przy użyciu algorytmu DES.

    Obsługiwane tryby:
    - CBC (Cipher Block Chaining)
    - CFB (Cipher Feedback)

    Klucz DES musi mieć dokładnie 8 bajtów.
    """

    def __init__(self, key):
        """
        Inicjalizuje obiekt DESCipher z podanym kluczem.

        Args:
            key (bytes): Klucz DES (dokładnie 8 bajtów).
        
        Raises:
            ValueError: Jeśli klucz nie ma odpowiedniej długości.
        """
        if len(key) != 8:
            raise ValueError("Klucz DES musi mieć dokładnie 8 bajtów.")
        self.key = key

    def encrypt_block_mode(self, plaintext):
        """
        Szyfruje dane w trybie blokowym CBC (Cipher Block Chaining).

        Args:
            plaintext (str): Tekst do zaszyfrowania.
        
        Returns:
            str: Zaszyfrowany tekst zakodowany w Base64.
        """
        # Tworzenie obiektu szyfrującego w trybie CBC
        cipher = DES.new(self.key, DES.MODE_CBC)
        iv = cipher.iv  # Wektor inicjalizujący (IV)

        # Dodanie wypełnienia do tekstu zgodnie z rozmiarem bloku DES
        padded_data = pad(plaintext.encode(), DES.block_size)

        # Szyfrowanie danych
        ciphertext = cipher.encrypt(padded_data)

        # Połączenie IV z zaszyfrowanymi danymi i zakodowanie ich w Base64
        encrypted_data = iv + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')

    def decrypt_block_mode(self, b64_ciphertext):
        """
        Odszyfrowuje dane zaszyfrowane w trybie CBC (Cipher Block Chaining).

        Args:
            b64_ciphertext (str): Zaszyfrowany tekst zakodowany w Base64.
        
        Returns:
            str: Odszyfrowany tekst.
        """
        # Dekodowanie danych Base64
        ciphertext = base64.b64decode(b64_ciphertext)

        # Wyodrębnienie wektora inicjalizującego (IV)
        iv = ciphertext[:DES.block_size]

        # Tworzenie obiektu deszyfrującego w trybie CBC
        cipher = DES.new(self.key, DES.MODE_CBC, iv)

        # Deszyfrowanie danych i usunięcie wypełnienia
        decrypted_data = unpad(cipher.decrypt(ciphertext[DES.block_size:]), DES.block_size)
        return decrypted_data.decode()

    def encrypt_stream_mode(self, plaintext):
        """
        Szyfruje dane w trybie strumieniowym CFB (Cipher Feedback).

        Args:
            plaintext (str): Tekst do zaszyfrowania.
        
        Returns:
            str: Zaszyfrowany tekst zakodowany w Base64.
        """
        # Tworzenie obiektu szyfrującego w trybie CFB
        cipher = DES.new(self.key, DES.MODE_CFB)
        iv = cipher.iv  # Wektor inicjalizujący (IV)

        # Szyfrowanie danych bez potrzeby dodawania wypełnienia
        ciphertext = cipher.encrypt(plaintext.encode())

        # Połączenie IV z zaszyfrowanymi danymi i zakodowanie ich w Base64
        encrypted_data = iv + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')

    def decrypt_stream_mode(self, b64_ciphertext):
        """
        Odszyfrowuje dane zaszyfrowane w trybie CFB (Cipher Feedback).

        Args:
            b64_ciphertext (str): Zaszyfrowany tekst zakodowany w Base64.
        
        Returns:
            str: Odszyfrowany tekst.
        """
        # Dekodowanie danych Base64
        ciphertext = base64.b64decode(b64_ciphertext)

        # Wyodrębnienie wektora inicjalizującego (IV)
        iv = ciphertext[:DES.block_size]

        # Tworzenie obiektu deszyfrującego w trybie CFB
        cipher = DES.new(self.key, DES.MODE_CFB, iv)

        # Deszyfrowanie danych
        decrypted_data = cipher.decrypt(ciphertext[DES.block_size:])
        return decrypted_data.decode()
