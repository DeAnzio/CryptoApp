from facades.Decryptor import Decryptor
from facades.Encryptor import Encryptor


class CaesarCipher(Encryptor, Decryptor):
    def __init__(self, key: int):
        self.key = key;

    def encrypt(self, plainText: str) -> str:
        result = ""
        for char in plainText:
            if char.isalpha():
                base = ord('A') if char.isupper() else  ord('a')
                result += chr((ord(char) - base + self.key) % 26 + base)
            else:
                result += char

        return result

    def decrypt(self, plainText: str) -> str:
        self.key *= -1
        result = self.encrypt(plainText)
        self.key += -1

        return result
