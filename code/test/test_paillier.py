# https://python-paillier.readthedocs.io/en/develop/usage.html
from benchmark import profile_and_monitor
from phe import paillier
import random

MESSAGE_SIZE = 2**10
MESSAGE_NB = 2**8
MESSAGES = [random.getrandbits(MESSAGE_SIZE) for _ in range(MESSAGE_NB)]

KEY_LENGTH = 2**12

SCALAR = 2.9

# Role1
def pheEncryptDecrypt():
    print("> Key Generation")
    public_key, private_key = paillier.generate_paillier_keypair(n_length=KEY_LENGTH)

    print("> Encrypting")
    encrypted_number_list = [public_key.encrypt(message) for message in MESSAGES]

    print("> Decrypting")
    decrypted_number_list = [private_key.decrypt(message) for message in encrypted_number_list]

    return public_key, private_key, encrypted_number_list, decrypted_number_list

# Role2
def additionEncryptedNumberScalar(encrypted_numbers, scalar):
    return [enc_num + scalar for enc_num in encrypted_numbers]

def additionEncryptedNumber(encrypted_numbers1, encrypted_numbers2):
    return [enc_num1 + enc_num2 for enc_num1, enc_num2 in zip(encrypted_numbers1, encrypted_numbers2)]

def multiplicationEncryptedNumberScalar(encrypted_numbers, scalar):
    return [enc_num * scalar for enc_num in encrypted_numbers]

def client():
    # Generate public and secret keys
    key_length = 4096
    public_key, private_key = paillier.generate_paillier_keypair(n_length=key_length)

    # Encrypt data and scalar
    data = [60, 66, 73, 81, 90]
    scalar = 2.1

    # Encrypt the data
    encrypted_data = [public_key.encrypt(x) for x in data]
    encrypted_scalar = public_key.encrypt(scalar)

    encrypted_result = server(encrypted_data, encrypted_scalar)

    # Decrypt the result
    decrypted_result = [private_key.decrypt(x) for x in encrypted_result]
    print(decrypted_result)

def server(encrypted_data, encrypted_scalar):
    # Add encrypted data and scalar
    encrypted_add = [x + encrypted_scalar for x in encrypted_data]
    return encrypted_add

if __name__ == "__main__":
    client()