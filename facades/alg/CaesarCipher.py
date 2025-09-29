from facades.Decryptor import Decryptor
from facades.Encryptor import Encryptor


class CaesarCipher(Encryptor, Decryptor):
    def __init__(self, key: int):
        self.key = key;

    def encrypt(self, plainText: str) -> str:
        return "haii"

    def decrypt(self, plainText: str) -> str:
        return "hello"

