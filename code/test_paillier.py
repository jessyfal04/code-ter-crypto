# https://python-paillier.readthedocs.io/en/develop/usage.html
from benchmark import profile_and_monitor
from phe import paillier
import random

MESSAGE_SIZE = 2**10
MESSAGE_NB = 2**8
MESSAGES = [random.getrandbits(MESSAGE_SIZE) for _ in range(MESSAGE_NB)]

KEY_LENGTH = 2**12

SCALAR = 5

# Role1
@profile_and_monitor
def pheEncryptDecrypt():
    print("> Key Generation")
    public_key, private_key = paillier.generate_paillier_keypair(n_length=KEY_LENGTH)

    print("> Encrypting")
    encrypted_number_list = [public_key.encrypt(message) for message in MESSAGES]

    print("> Decrypting")
    decrypted_number_list = [private_key.decrypt(message) for message in encrypted_number_list]

    return public_key, private_key, encrypted_number_list, decrypted_number_list

# Role2
@profile_and_monitor
def additionEncryptedNumberScalar(encrypted_numbers, scalar):
    return [enc_num + scalar for enc_num in encrypted_numbers]

@profile_and_monitor
def additionEncryptedNumber(encrypted_numbers1, encrypted_numbers2):
    return [enc_num1 + enc_num2 for enc_num1, enc_num2 in zip(encrypted_numbers1, encrypted_numbers2)]

@profile_and_monitor
def multiplicationEncryptedNumberScalar(encrypted_numbers, scalar):
    return [enc_num * scalar for enc_num in encrypted_numbers]

if __name__ == '__main__':
    public_key, private_key, encrypted_number_list, _ = pheEncryptDecrypt()
    encrypted_result_add_scalar = additionEncryptedNumberScalar(encrypted_number_list, SCALAR)
    encrypted_result_add = additionEncryptedNumber(encrypted_number_list, encrypted_number_list[::-1])
    encrypted_result_mul_scalar = multiplicationEncryptedNumberScalar(encrypted_number_list, SCALAR)