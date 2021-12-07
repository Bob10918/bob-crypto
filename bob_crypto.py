#!/usr/local/bin/python3.8

# require pycrypto~=2.6.1 

from Crypto.Cipher import AES
import hashlib
import getpass

class WrongPasswordException(Exception):
    pass

class BobCrypto():
    AES_MODE = AES.MODE_CBC
    IV = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    HASH_ALGO = 'sha512'
    HASH_ITERATIONS = 100000
    SALT = b'hfquigrfcniufhqceuqxqnqxq'
    
    def __init__(self, encrypted_secret: bytes, hashed_secret: bytes) -> None:
        self._password = getpass.getpass("Manda password: ")
        self._hashed_secret = hashed_secret
        self.secret = self.decrypt(encrypted_secret)
        self.check_correct_secret(self.secret, self._hashed_secret)

    def decrypt(self, message: bytes) -> str:
        return AES.new(self._password.encode(), self.AES_MODE, self.IV).decrypt(message).decode()

    def check_correct_secret(self, secret: str, hashed_secret: bytes):
        if hashlib.pbkdf2_hmac(self.HASH_ALGO, secret.encode(), self.SALT, self.HASH_ITERATIONS) != hashed_secret:
            raise WrongPasswordException



def encrypt(password: bytes, message: bytes) -> bytes:
    return AES.new(password, BobCrypto.AES_MODE, BobCrypto.IV).encrypt(message)

def hash(secret: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(BobCrypto.HASH_ALGO, secret, BobCrypto.SALT, BobCrypto.HASH_ITERATIONS)

def encrypt_and_hash():
    password = getpass.getpass("Manda password: ").encode()
    secret = getpass.getpass("Secret: ").encode()
    print(f"Encrypted secret: {encrypt(password, secret)}")
    print(f"Hashed secret: {hash(secret)}")
