#!/usr/local/bin/python3.8

from typing import List, Tuple, Optional
import getpass
import secrets
from uuid import uuid4

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENCODING = 'utf-8'

REAL_KEY_LENGTH = 256  # bits
DERIVED_KEY_LENGTH = 256  # bits
SALT_LENGTH = 32  # bytes
NONCE_LENGTH = 32  # bytes

# encrypted string symbols and identifiers
ES_ASSIGN_SYMBOL = '='
ES_SEPARATOR_SYMBOL = ';'
ES_NONCE_IDENTIFIER = "n"
ES_EDATA_IDENTIFIER = "ed"
ES_SALT_IDENTIFIER = "s"


class InvalidKeyStringException(Exception):
    pass


def generate_encrypted_key_string(from_password: bool = False, application_name: str = None, username: str = None) -> Tuple[str, str]:
    # salt is always included even if not used to not give hints to the adversary
    salt = secrets.token_bytes(SALT_LENGTH)
    if from_password:
        # https://security.stackexchange.com/questions/38828/how-can-i-securely-convert-a-string-password-to-a-key-used-in-aes
        password = getpass.getpass("Manda password: ")
        encrypting_key = derive_key(password.encode(ENCODING), salt)
    else:
        encrypting_key = bytes.fromhex(getpass.getpass("Manda key: "))
    real_key = AESGCM.generate_key(REAL_KEY_LENGTH)
    aesgcm = AESGCM(encrypting_key)
    nonce = secrets.token_bytes(NONCE_LENGTH)
    uuid = uuid4().hex
    encrypted_key = aesgcm.encrypt(nonce, real_key, canonicalize_associated_data([application_name, username, uuid]))
    return dump_encrypted_string(nonce, encrypted_key, salt), uuid

def dump_encrypted_string(nonce: bytes, encrypted_data: bytes, salt: bytes = None) -> str:
    dumped = f"{ES_NONCE_IDENTIFIER}{ES_ASSIGN_SYMBOL}{nonce.hex()}{ES_SEPARATOR_SYMBOL}{ES_EDATA_IDENTIFIER}{ES_ASSIGN_SYMBOL}{encrypted_data.hex()}"
    if salt is not None:
        dumped += f"{ES_SEPARATOR_SYMBOL}{ES_SALT_IDENTIFIER}{ES_ASSIGN_SYMBOL}{salt.hex()}"
    return dumped

def parse_encrypted_string(encrypted_string: str) -> Tuple[bytes, bytes, Optional[bytes]]:
    ekstring_splitted = encrypted_string.split(ES_SEPARATOR_SYMBOL)
    if len(ekstring_splitted) < 2:
        raise InvalidKeyStringException
    if not ekstring_splitted[0].startswith(f"{ES_NONCE_IDENTIFIER}{ES_ASSIGN_SYMBOL}"):
        raise InvalidKeyStringException
    nonce =  bytes.fromhex(ekstring_splitted[0].replace(f"{ES_NONCE_IDENTIFIER}{ES_ASSIGN_SYMBOL}", ""))
    if not ekstring_splitted[1].startswith(f"{ES_EDATA_IDENTIFIER}{ES_ASSIGN_SYMBOL}"):
        raise InvalidKeyStringException
    encrypted_data = bytes.fromhex(ekstring_splitted[1].replace(f"{ES_EDATA_IDENTIFIER}{ES_ASSIGN_SYMBOL}", ""))
    if len(ekstring_splitted) > 2:
        if not ekstring_splitted[2].startswith(f"{ES_SALT_IDENTIFIER}{ES_ASSIGN_SYMBOL}"):
            raise InvalidKeyStringException
        salt = bytes.fromhex(ekstring_splitted[2].replace(f"{ES_SALT_IDENTIFIER}{ES_ASSIGN_SYMBOL}", ""))
    else:
        salt = None
    return nonce, encrypted_data, salt

def derive_key(input: bytes, salt: bytes) -> bytes:
    # https://soatok.blog/2022/12/29/what-we-do-in-the-etc-shadow-cryptography-with-passwords/
    kdf = Scrypt(
        salt=salt,
        length=int(DERIVED_KEY_LENGTH/8),
        n=2097152, # 2**21
        r=8,
        p=1
    )
    derived_key = kdf.derive(input)
    return derived_key

def canonicalize_associated_data(associated_data: List[Optional[str]]) -> bytes:
    canonicalized = ""
    for data in associated_data:
        clean_data = data if data is not None else ""
        canonicalized += f"_{clean_data}:{len(clean_data)}"
    if canonicalized.startswith('_'):
        canonicalized = canonicalized[1:]
    return canonicalized.encode(ENCODING)


class BobCrypto():    
    def __init__(self,
                 encrypted_key_string: str,
                 uuid: str,
                 from_password: bool = False,
                 application_name: str = None,
                 username: str = None) -> None:
        """The input key MUST be a cryptographic random bytes string hex formatted. The only exception is when the 'from_password' parameter is 
        set to True, but this is discouraged. It is better to use a true random key and store it in a safe place.
        Try to fill in the optional parameters 'application_name' and 'username' to provide the best integrity to your password."""

        nonce, encrypted_key, salt = parse_encrypted_string(encrypted_key_string)
        if from_password:
            password = getpass.getpass("Manda password: ")
            key = derive_key(password.encode(ENCODING), salt)
        else:
            key = bytes.fromhex(getpass.getpass("Manda key: "))
        aesgcm = AESGCM(key)
        self._real_key = aesgcm.decrypt(nonce, encrypted_key, canonicalize_associated_data([application_name, username, uuid]))

    def encrypt(self, data: str, associated_data: List[str]) -> str:
        salt = secrets.token_bytes(SALT_LENGTH)
        key = derive_key(self._real_key, salt)
        nonce = secrets.token_bytes(NONCE_LENGTH)
        aesgcm = AESGCM(key)
        encrypted_data = aesgcm.encrypt(nonce, data.encode(ENCODING), canonicalize_associated_data(associated_data))
        return dump_encrypted_string(nonce, encrypted_data, salt)

    def decrypt(self, encrypted_string: str, associated_data: List[str]) -> str:
        nonce, encrypted_data, salt = parse_encrypted_string(encrypted_string)
        key = derive_key(self._real_key, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, encrypted_data, canonicalize_associated_data(associated_data)).decode(ENCODING)
