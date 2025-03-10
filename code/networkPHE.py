import socket
import random
import argparse
import json

from phe import paillier

import benchmark
from benchmark import profile_and_monitor

# Configuration
MESSAGE_SIZE = 2**10
MESSAGE_NB = 2**2
KEY_LENGTH = 2**12

PORT = 12342  # Port for communication
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
    global network_bytes_sent
    data_bytes = data.encode('utf-8')
    benchmark.network_bytes_sent += len(data_bytes)
    sock.sendall(data_bytes)
    
def receive_data(sock):
    global network_bytes_received
    data = sock.recv(BUFFER_SIZE)
    decoded_data = data.decode('utf-8')
    benchmark.network_bytes_received += len(decoded_data.encode('utf-8'))
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

@profile_and_monitor
def client(server_ip):
    # Generate messages and keys
    messages = [random.getrandbits(MESSAGE_SIZE) for _ in range(MESSAGE_NB)]
    scalar = random.getrandbits(1024)
    operation = "add"

    public_key, private_key = generate_keypair()
    encrypted_messages = encrypt_messages(public_key, messages)
    
    # Serialize data
    serialized_data = serialize_data(public_key, encrypted_messages)
    
    # Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, PORT))
    
    print("> Sending DataToCompute to Server")
    # Prepare data to send
    data_to_compute = {
        'serialized_data': serialized_data,
        'scalar': scalar,
        'operation': operation
    }
    send_data(sock, json.dumps(data_to_compute))

    # Receive data from server
    print("> Receiving Serialized Data from Server")
    serialized_data = receive_data(sock)
    _, encrypted_result = deserialize_data(serialized_data)

    # Decrypt the result with the private key
    decrypted_result = decrypt_messages(private_key, encrypted_result)

    # Compare wit h expected result
    if operation == "add":
        expected_result = [msg + scalar for msg in messages]  # The operation the server performed
    else:
        raise ValueError(f"Operation {operation} not supported!")
    
    # Print and compare results
    ok = True
    for i, (decrypted, expected) in enumerate(zip(decrypted_result, expected_result)):
        if decrypted != expected:
            print(f"{i} Decrypted value does not match expected value")
            print(f"Decrypted: {decrypted}")
            print(f"Expected: {expected}")
    if ok:
        print("All decrypted values match expected values")
    
    sock.close()

@profile_and_monitor
def server():
    # Create socket server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", PORT))
    sock.listen(1)
    print("> Waiting for client connection...")
    
    conn, _ = sock.accept()
    print("> Receiving DataToCompute Data")
    data_to_compute = receive_data(conn)
    
    data_to_compute = json.loads(data_to_compute)

    serialized_data = data_to_compute['serialized_data']
    public_key, encrypted_messages = deserialize_data(serialized_data)

    scalar = data_to_compute['scalar']
    operation = data_to_compute['operation']
    
    # Operations: Add Scalar to each encrypted message
    print("> Performing Homomorphic Operations")
    if operation == 'add':
        encrypted_result = [msg + scalar for msg in encrypted_messages]
    else:
        raise ValueError(f"Operation {operation} not supported!")
    
    # Serialize the result and send it back to the client
    serialized_data = serialize_data(public_key, encrypted_result)
    print("> Sending result back to client")
    send_data(conn, serialized_data)
    
    conn.close()
    sock.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action='store_true', help="Run as server")
    parser.add_argument("--client", type=str, help="Run as client, specify server IP")
    args = parser.parse_args()

    if args.server:
        server()
    elif args.client:
        client(args.client)
    else:
        print("Please specify either --server or --client <server_ip>")
        exit(1)

   
