from typing import List
from bob_crypto import BobCrypto, generate_encrypted_key_string

def test(test_data: str = 'bobcrypto', from_password: bool = True, application_name: str = "bobcrypto-test", 
         username: str = "Bob", associated_data: List[str] = ["bobcrypto", "test"]):
    encrypted_key_string, uuid = generate_encrypted_key_string(from_password, application_name, username)
    print(f"Encrypted key string: {encrypted_key_string}")
    print(f"Generated uuid: {uuid}")
    bc = BobCrypto(encrypted_key_string, uuid, from_password, application_name, username)
    print(f"Encrypting test data '{test_data}':...")
    encrypted_data = bc.encrypt(test_data, associated_data)
    print(f"Encrypted test data: {encrypted_data}")
    print(f"Decrypting test data:...")
    decrypted_data = bc.decrypt(encrypted_data, associated_data)
    print(f"Decrypted test data: '{decrypted_data}'")
    if decrypted_data == test_data:
        print("Success!")
    else:
        print("Azz")


if __name__ == '__main__':
    test()