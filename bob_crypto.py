#!/usr/local/bin/python3.8

# require pycrypto~=2.6.1 

from typing import Tuple
from Crypto.Cipher import AES
import hashlib
import getpass
import secrets

class WrongPasswordException(Exception):
    pass

class BobCrypto():
    AES_MODE = AES.MODE_CBC
    IV = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    HASH_ALGO = 'sha512'
    HASH_ITERATIONS = 100000
    SALT = b'hfquigrfcniufhqceuqxqnqxq'
    ENCODING = 'utf-8'
    
    def __init__(self, encrypted_secret: bytes, hashed_secret: bytes, padding_length: int = None) -> None:
        self._password = getpass.getpass("Manda password: ")
        self._hashed_secret = hashed_secret
        self.secret = self.decrypt(encrypted_secret, padding_length)
        self.check_correct_secret(self.secret, self._hashed_secret)

    def decrypt(self, message: bytes, padding_length: int = None) -> str:
        decrypted = AES.new(self._password.encode(self.ENCODING), self.AES_MODE, self.IV).decrypt(message)
        if padding_length:
            return decrypted[:-padding_length].decode(self.ENCODING)
        else:
            return decrypted.decode(self.ENCODING)

    def check_correct_secret(self, secret: str, hashed_secret: bytes):
        if hashlib.pbkdf2_hmac(self.HASH_ALGO, secret.encode(self.ENCODING), self.SALT, self.HASH_ITERATIONS) != hashed_secret:
            raise WrongPasswordException



def encrypt(password: bytes, message: bytes) -> Tuple[bytes, int]:
    extra_bytes = len(message) % 16
    if extra_bytes != 0:
        padding = 16 - extra_bytes
        message = message + secrets.token_bytes(padding)
    return AES.new(password, BobCrypto.AES_MODE, BobCrypto.IV).encrypt(message), padding

def hash(secret: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(BobCrypto.HASH_ALGO, secret, BobCrypto.SALT, BobCrypto.HASH_ITERATIONS)

def encrypt_and_hash():
    password = getpass.getpass("Manda password: ").encode(BobCrypto.ENCODING)
    secret = getpass.getpass("Secret: ").encode(BobCrypto.ENCODING)
    encrypted, padding = encrypt(password, secret)
    print(f"Encrypted secret: {encrypted}")
    print(f"Applied padding: {padding} bytes")
    print(f"Hashed secret: {hash(secret)}")
