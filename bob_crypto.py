#!/usr/local/bin/python3.8

# require cryptography~=39.0.0

from typing import Tuple, Optional
import getpass
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENCODING = 'utf-8'

REAL_KEY_LENGTH = 256  # bits
DERIVED_KEY_LENGTH = 256  # bits
SALT_LENGTH = 32  # bytes
DERIVE_KEY_HASH_ALGO = hashes.SHA3_512
DERIVE_KEY_ITERATIONS = 10**6
NONCE_LENGTH = 32  # bytes
ASSOCIATED_DATA = 'bobcryptoad'.encode(ENCODING)

# encrypted string symbols and identifiers
ES_ASSIGN_SYMBOL = '='
ES_SEPARATOR_SYMBOL = ';'
ES_NONCE_IDENTIFIER = "n"
ES_EDATA_IDENTIFIER = "ed"
ES_SALT_IDENTIFIER = "s"


class InvalidKeyStringException(Exception):
    pass


def generate_encrypted_key_string() -> str:
    # https://security.stackexchange.com/questions/38828/how-can-i-securely-convert-a-string-password-to-a-key-used-in-aes
    password = getpass.getpass("Manda password: ")
    real_key = AESGCM.generate_key(REAL_KEY_LENGTH)
    salt = secrets.token_bytes(SALT_LENGTH)
    derived_key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(derived_key)
    nonce = secrets.token_bytes(NONCE_LENGTH)
    encrypted_key = aesgcm.encrypt(nonce, real_key, ASSOCIATED_DATA)
    return dump_encrypted_string(nonce, encrypted_key, salt)

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

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=DERIVE_KEY_HASH_ALGO(),
        length=int(DERIVED_KEY_LENGTH/8),
        salt=salt,
        iterations=DERIVE_KEY_ITERATIONS
    )
    derived_key = kdf.derive(password.encode(ENCODING))
    return derived_key


class BobCrypto():    
    def __init__(self, encrypted_key_string: str) -> None:
        nonce, encrypted_key, salt = parse_encrypted_string(encrypted_key_string)
        password = getpass.getpass("Manda password: ")
        derived_key = derive_key_from_password(password, salt)
        aesgcm = AESGCM(derived_key)
        self._real_key = aesgcm.decrypt(nonce, encrypted_key, ASSOCIATED_DATA)

    def encrypt(self, data: str) -> str:
        aesgcm = AESGCM(self._real_key)
        nonce = secrets.token_bytes(NONCE_LENGTH)
        encrypted_data = aesgcm.encrypt(nonce, data.encode(ENCODING), ASSOCIATED_DATA)
        return dump_encrypted_string(nonce, encrypted_data)

    def decrypt(self, encrypted_string: str) -> str:
        aesgcm = AESGCM(self._real_key)
        nonce, encrypted_data, _ = parse_encrypted_string(encrypted_string)
        return aesgcm.decrypt(nonce, encrypted_data, ASSOCIATED_DATA).decode(ENCODING)


def test(test_data: str = 'bobcrypto'):
    encrypted_key_string = generate_encrypted_key_string()
    print(f"Encrypted key string: {encrypted_key_string}")
    bc = BobCrypto(encrypted_key_string)
    print(f"Encrypting test data '{test_data}':...")
    encrypted_data = bc.encrypt(test_data)
    print(f"Encrypted test data: {encrypted_data}")
    print(f"Decrypting test data:...")
    decrypted_data = bc.decrypt(encrypted_data)
    print(f"Decrypted test data: '{decrypted_data}'")
    if decrypted_data == test_data:
        print("Success!")
    else:
        print("Azz")
