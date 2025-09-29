from abc import ABC, abstractmethod

class Decryptor(ABC):
    @abstractmethod
    def decrypt(self, plainText: str) -> str:
        pass
