#!/usr/local/bin/python3.8

from typing import List, Tuple, Optional
import getpass
import secrets
from uuid import uuid4

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# constants
CHACHA20_KEY_LENGTH = 32  # bytes
NONCE_LENGTH = 12  # bytes

# modifiable parameters
ENCODING = 'utf-8'
DERIVE_KEY_SALT = b'bob_crypto_\xcd\xf16\xf0BZ\n\xbf\xf2\x9c\x13\x82N\xd6{\x05\xc2\xf2W|\x98'  # 32 bytes
SALT_LENGTH = 32  # bytes
HKDF_EXPAND_ALGORITHM = hashes.SHA3_512

# encrypted string symbols and identifiers
ES_ASSIGN_SYMBOL = '='
ES_SEPARATOR_SYMBOL = ';'
ES_NONCE_IDENTIFIER = "n"
ES_EDATA_IDENTIFIER = "ed"
ES_SALT_IDENTIFIER = "s"


class InvalidKeyStringException(Exception):
    pass


def generate_encrypted_key_string(from_password: bool = False, application_name: str = None, username: str = None) -> Tuple[str, str]:
    # salt is fixed to achieve KDF security: https://soatok.blog/2021/11/17/understanding-hkdf/
    if from_password:
        # https://security.stackexchange.com/questions/38828/how-can-i-securely-convert-a-string-password-to-a-key-used-in-aes
        password = getpass.getpass("Manda password: ")
        encrypting_key = derive_key_from_password(password.encode(ENCODING), DERIVE_KEY_SALT)
    else:
        encrypting_key = bytes.fromhex(getpass.getpass("Manda key: "))
    real_key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(encrypting_key)
    nonce = secrets.token_bytes(NONCE_LENGTH)
    uuid = uuid4().hex
    encrypted_key = chacha.encrypt(nonce, real_key, canonicalize_associated_data([application_name, username, uuid]))
    return dump_encrypted_string(nonce, encrypted_key), uuid

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

def derive_key_from_password(input: bytes, salt: bytes) -> bytes:
    # https://soatok.blog/2022/12/29/what-we-do-in-the-etc-shadow-cryptography-with-passwords/
    kdf = Scrypt(
        salt=salt,
        length=CHACHA20_KEY_LENGTH,
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

        nonce, encrypted_key, _ = parse_encrypted_string(encrypted_key_string)
        if from_password:
            password = getpass.getpass("Manda password: ")
            key = derive_key_from_password(password.encode(ENCODING), DERIVE_KEY_SALT)
        else:
            key = bytes.fromhex(getpass.getpass("Manda key: "))
        chacha = ChaCha20Poly1305(key)
        self._real_key = chacha.decrypt(nonce, encrypted_key, canonicalize_associated_data([application_name, username, uuid]))

    def _expand_key(self, info: bytes) -> bytes:
        hkdf = HKDFExpand(
            algorithm=HKDF_EXPAND_ALGORITHM(),
            length=CHACHA20_KEY_LENGTH,
            info=info
        )
        return hkdf.derive(self._real_key)

    def encrypt(self, data: str, associated_data: List[str]) -> str:
        # https://soatok.blog/2021/11/17/understanding-hkdf/
        salt = secrets.token_bytes(SALT_LENGTH)
        key = self._expand_key(canonicalize_associated_data(associated_data + [salt]))
        nonce = secrets.token_bytes(NONCE_LENGTH)
        chacha = ChaCha20Poly1305(key)
        encrypted_data = chacha.encrypt(nonce, data.encode(ENCODING), canonicalize_associated_data(associated_data))
        return dump_encrypted_string(nonce, encrypted_data, salt)

    def decrypt(self, encrypted_string: str, associated_data: List[str]) -> str:
        # https://soatok.blog/2021/11/17/understanding-hkdf/
        nonce, encrypted_data, salt = parse_encrypted_string(encrypted_string)
        key = self._expand_key(canonicalize_associated_data(associated_data + [salt]))
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(nonce, encrypted_data, canonicalize_associated_data(associated_data)).decode(ENCODING)
    
    def interactive_encrypt(self):
        data = getpass.getpass("Inserisci plaintext: ")
        associated_data = []
        while (ad := input("Inserisci aad (lascia vuoto per terminare): ")) != '':
            associated_data.append(ad)
        print(self.encrypt(data, associated_data))
