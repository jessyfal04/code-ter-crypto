import socket
import random
import argparse
import json

from phe import paillier
import benchmark
from benchmark import profile_and_monitor

# --- Homomorphic Operation Functions ---

def add_encrypted_scalar(
    enc: paillier.EncryptedNumber, scalar: int
) -> paillier.EncryptedNumber:
    """
    Homomorphically add a scalar to an EncryptedNumber.
    :param enc: EncryptedNumber instance.
    :param scalar: Plain integer value.
    :return: New EncryptedNumber instance representing the sum.
    """
    return enc + scalar

def add_encrypted_numbers(
    enc1: paillier.EncryptedNumber, enc2: paillier.EncryptedNumber
) -> paillier.EncryptedNumber:
    """
    Homomorphically add two EncryptedNumber instances.
    Both numbers must be encrypted with the same public key.
    :param enc1: First EncryptedNumber.
    :param enc2: Second EncryptedNumber.
    :return: New EncryptedNumber instance representing the sum.
    """
    return enc1 + enc2

def multiply_encrypted_by_scalar(
    enc: paillier.EncryptedNumber, scalar: int
) -> paillier.EncryptedNumber:
    """
    Homomorphically multiply an EncryptedNumber by a scalar.
    :param enc: EncryptedNumber instance.
    :param scalar: Scalar multiplier.
    :return: New EncryptedNumber instance representing the product.
    """
    return enc * scalar

def divide_encrypted_by_scalar(
    enc: paillier.EncryptedNumber, scalar: int
) -> paillier.EncryptedNumber:
    """
    Homomorphically divide an EncryptedNumber by a scalar.
    Division is implemented as multiplication by the reciprocal.
    :param enc: EncryptedNumber instance.
    :param scalar: Divisor (must be non-zero).
    :return: New EncryptedNumber instance representing the division result.
    :raises ValueError: If scalar is zero.
    """
    if scalar == 0:
        raise ValueError("Division by zero is not allowed.")
    reciprocal = 1 / scalar
    return enc * reciprocal

# --- End of Homomorphic Operation Functions ---

# Configuration
NB_RUNS = 1

MESSAGE_SIZE = 2**10
MESSAGE_NB = 2**2
KEY_LENGTH = 2**12

PORT = 12352  # Port for communication
BUFFER_SIZE = 2**31  # Buffer size for message transfer

def generate_keypair():
    print(f"> Generating Keypair of length {KEY_LENGTH}")
    public_key, private_key = paillier.generate_paillier_keypair(n_length=KEY_LENGTH)
    return public_key, private_key

def encrypt_messages(public_key, messages):
    print(f"> Encrypting {len(messages)} Messages")
    return [public_key.encrypt(m) for m in messages]

def decrypt_messages(private_key, encrypted_messages):
    print(f"> Decrypting {len(encrypted_messages)} Messages")
    return [private_key.decrypt(m) for m in encrypted_messages]

def send_data(sock, data):
    global current_network_bytes_sent
    data_bytes = data.encode('utf-8')
    benchmark.current_network_bytes_sent += len(data_bytes)
    sock.sendall(data_bytes)
    
def receive_data(sock):
    global current_network_bytes_received
    data = sock.recv(BUFFER_SIZE)
    decoded_data = data.decode('utf-8')
    benchmark.current_network_bytes_received += len(decoded_data.encode('utf-8'))
    return decoded_data

def serialize_data(public_key, encrypted_number_list):
    print("> Serializing data")
    enc_with_one_pub_key = {}
    enc_with_one_pub_key['public_key'] = {'g': public_key.g, 'n': public_key.n}
    enc_with_one_pub_key['values'] = [
        (str(x.ciphertext()), x.exponent) for x in encrypted_number_list
    ]
    return json.dumps(enc_with_one_pub_key)

def deserialize_data(serialized_data):
    print("> Deserializing data")
    received_dict = json.loads(serialized_data)
    pk = received_dict['public_key']
    public_key_rec = paillier.PaillierPublicKey(n=int(pk['n']))
    enc_nums_rec = [
        paillier.EncryptedNumber(public_key_rec, int(x[0]), int(x[1]))
        for x in received_dict['values']
    ]
    return public_key_rec, enc_nums_rec

# Client / Server
@profile_and_monitor(number=NB_RUNS)
def client(server_ip, operation=None):
    # Generate messages and keys
    messages = [random.getrandbits(MESSAGE_SIZE) for _ in range(MESSAGE_NB)]
    scalar = random.getrandbits(1024)

    public_key, private_key = generate_keypair()
    encrypted_messages = encrypt_messages(public_key, messages)
    
    # Prepare the data payload
    print(f"> Computing {operation} with {MESSAGE_NB} messages")
    data_to_compute = {
        'operation': operation,
        'scalar': scalar
    }
    
    if operation in ['add', 'mul', 'div']:
        # For operations that use a single encrypted message list
        data_to_compute['serialized_data'] = serialize_data(public_key, encrypted_messages)
    elif operation == 'add_encrypted':
        # For element-wise addition of two encrypted message lists, send a second list.
        # (For demonstration, we use the same list; in practice, they may be different.)
        data_to_compute['serialized_data'] = serialize_data(public_key, encrypted_messages)
        data_to_compute['serialized_data2'] = serialize_data(public_key, encrypted_messages)
    else:
        raise ValueError(f"Operation {operation} not supported by client!")
    
    # Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, PORT+benchmark.current_run))
    
    print("> Sending DataToCompute to Server")
    send_data(sock, json.dumps(data_to_compute))

    print("> Receiving Serialized Data from Server")
    serialized_data = receive_data(sock)
    
    # Deserialize the result (the result is a single encrypted message list)
    _, encrypted_result = deserialize_data(serialized_data)

    # Decrypt the result with the private key
    decrypted_result = decrypt_messages(private_key, encrypted_result)

    # Compute expected results locally
    if operation == "add":
        expected_result = [msg + scalar for msg in messages]
    elif operation == "add_encrypted":
        expected_result = [msg1 + msg2 for msg1, msg2 in zip(messages, messages)]
    elif operation == "mul":
        expected_result = [msg * scalar for msg in messages]
    elif operation == "div":
        reciprocal = 1 / scalar
        expected_result = [msg * reciprocal for msg in messages]
    else:
        raise ValueError(f"Operation {operation} not supported for expected result computation!")
    
    # Compare the decrypted results with the expected results
    ok = True
    for i, (decrypted, expected) in enumerate(zip(decrypted_result, expected_result)):
        if decrypted != expected:
            print(f"{i} Decrypted value does not match expected value")
            print(f"Decrypted: {decrypted}")
            print(f"Expected: {expected}")
            ok = False
    if ok:
        print("All decrypted values match expected values")
    
    sock.close()

@profile_and_monitor(number=NB_RUNS)
def server():
    # Create socket server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", PORT+benchmark.current_run))
    sock.listen(1)
    print("> Waiting for client connection...")
    
    conn, _ = sock.accept()
    print("> Receiving DataToCompute Data")
    data_to_compute = receive_data(conn)
    
    data_to_compute = json.loads(data_to_compute)
    operation = data_to_compute['operation']
    
    # Deserialize encrypted messages based on the operation
    if operation in ['add', 'mul', 'div']:
        serialized_data = data_to_compute['serialized_data']
        public_key, encrypted_messages = deserialize_data(serialized_data)
    elif operation == 'add_encrypted':
        serialized_data = data_to_compute['serialized_data']
        serialized_data2 = data_to_compute.get('serialized_data2')
        if not serialized_data2:
            raise ValueError("Operation 'add_encrypted' requires a second serialized data ('serialized_data2').")
        public_key, encrypted_messages = deserialize_data(serialized_data)
        _, encrypted_messages2 = deserialize_data(serialized_data2)
        if len(encrypted_messages) != len(encrypted_messages2):
            raise ValueError("Both encrypted message lists must be of the same length for 'add_encrypted'.")
    else:
        raise ValueError(f"Operation {operation} not supported!")
    
    scalar = data_to_compute['scalar']
    
    # Perform the requested homomorphic operation using the typed functions
    print("> Performing Homomorphic Operations")
    if operation == 'add':
        encrypted_result = [add_encrypted_scalar(msg, scalar) for msg in encrypted_messages]
    elif operation == 'add_encrypted':
        encrypted_result = [add_encrypted_numbers(msg1, msg2) for msg1, msg2 in zip(encrypted_messages, encrypted_messages2)]
    elif operation == 'mul':
        encrypted_result = [multiply_encrypted_by_scalar(msg, scalar) for msg in encrypted_messages]
    elif operation == 'div':
        encrypted_result = [divide_encrypted_by_scalar(msg, scalar) for msg in encrypted_messages]
    else:
        raise ValueError(f"Operation {operation} not supported!")
    
    # Serialize the result and send it back to the client
    serialized_data = serialize_data(public_key, encrypted_result)
    print("> Sending result back to client")
    send_data(conn, serialized_data)
    
    conn.close()
    sock.close()

# Main
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action='store_true', help="Run as server")
    parser.add_argument("--client", type=str, help="Run as client, specify server IP")
    # operation 
    parser.add_argument("--operation", type=str, help="Operation to perform: 'add', 'add_encrypted', 'mul', 'div'")
    args = parser.parse_args()

    operation = args.operation if args.operation else "add"
    
    if args.server:
        server()
    elif args.client:
        client(args.client, operation)
    else:
        print("Please specify either --server or --client <server_ip>")
        exit(1)
