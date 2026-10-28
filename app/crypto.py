from cryptography.fernet import Fernet


class FieldCipher:
    def __init__(self, key: str):
        self.fernet = Fernet(key.encode())

    def encrypt(self, plaintext: str) -> str:
        return self.fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        return self.fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
