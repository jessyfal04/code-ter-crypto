import socket
import random
import argparse
import json
import math

from phe import paillier
import benchmark
from benchmark import profile_and_monitor

# -----------------------------------------------------------
#               Homomorphic Operation Functions
# -----------------------------------------------------------

def add_encrypted_scalar(enc: paillier.EncryptedNumber, scalar: int) -> paillier.EncryptedNumber:
    return enc + scalar

def add_encrypted_numbers(enc1: paillier.EncryptedNumber, enc2: paillier.EncryptedNumber) -> paillier.EncryptedNumber:
    return enc1 + enc2

def multiply_encrypted_by_scalar(enc: paillier.EncryptedNumber, scalar: int) -> paillier.EncryptedNumber:
    return enc * scalar

def divide_encrypted_by_scalar(enc: paillier.EncryptedNumber, scalar: int) -> paillier.EncryptedNumber:
    if scalar == 0:
        raise ValueError("Division by zero is not allowed.")
    reciprocal = 1 / scalar
    return enc * reciprocal

# -----------------------------------------------------------
#                 Utility Functions
# -----------------------------------------------------------
# Networking
INITIAL_PORT = 12310  # Port for communication
COUNT_PORT = 0 # Counter for port allocation (incremented for each new connection)
BUFFER_SIZE = 2**31  # Buffer size for message transfer

def get_port():
    global COUNT_PORT
    COUNT_PORT += 1
    print(f"Port: {INITIAL_PORT + COUNT_PORT}")
    return INITIAL_PORT + COUNT_PORT

def send_data(sock, data):
    data_bytes = data.encode('utf-8')
    benchmark.current_network_bytes_sent += len(data_bytes)
    sock.sendall(data_bytes)
    
def receive_data(sock):
    data = sock.recv(BUFFER_SIZE)
    decoded_data = data.decode('utf-8')
    benchmark.current_network_bytes_received += len(decoded_data.encode('utf-8'))
    return decoded_data

# Paillier
def generate_keypair(key_length):
    print(f"> Generating Keypair of length {key_length}")
    public_key, private_key = paillier.generate_paillier_keypair(n_length=key_length)
    return public_key, private_key

def encrypt_messages(public_key, messages):
    print(f"> Encrypting {len(messages)} Messages")
    return [public_key.encrypt(m) for m in messages]

def decrypt_messages(private_key, encrypted_messages):
    print(f"> Decrypting {len(encrypted_messages)} Messages")
    return [private_key.decrypt(m) for m in encrypted_messages]

# Serialization
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

# -----------------------------------------------------------
#         Client and Server Logic 
# -----------------------------------------------------------
# Non-benchmarked function to prepare keys (Client side)
def prepare_client_data(key_length):
    """
    Prepares client data (key generation) outside of the benchmarked section.
    """
    public_key, private_key = generate_keypair(key_length)
    return public_key, private_key

# --------------------------
# Actual client operations we want to benchmark
def run_client_operations(server_ip, operation, public_key, private_key, config):
    """
    This function is the 'core' that we'll benchmark using profile_and_monitor.
    """
    nb_messages = config['msg_nb']
    msg_size = config['msg_size']

    scalar = random.getrandbits(1024)
    messages = [random.getrandbits(msg_size) for _ in range(nb_messages)]
    encrypted_messages = encrypt_messages(public_key, messages)

    print(f"> Computing {operation} with {nb_messages} messages")
    data_to_compute = {
        'operation': operation,
        'scalar': scalar
    }
    
    if operation in ['add', 'mul', 'div']:
        data_to_compute['serialized_data'] = serialize_data(public_key, encrypted_messages)
    elif operation == 'add_encrypted':
        data_to_compute['serialized_data'] = serialize_data(public_key, encrypted_messages)
        data_to_compute['serialized_data2'] = serialize_data(public_key, encrypted_messages)
    else:
        raise ValueError(f"Operation {operation} not supported by client!")
    
    # Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, get_port()))
    
    print("> Sending DataToCompute to Server")
    send_data(sock, json.dumps(data_to_compute))

    print("> Receiving Serialized Data from Server")
    serialized_data = receive_data(sock)
    sock.close()
    
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
        if decrypted != expected if isinstance(expected, int) else not math.isclose(decrypted, expected, rel_tol=1e-5):
            print(f"{i} Decrypted value does not match expected value")
            print(f"Decrypted: {decrypted}")
            print(f"Expected: {expected}")
            print(f"Int : {isinstance(expected, int)}")
            ok = False
    if ok:
        print("All decrypted values match expected values")

def client(server_ip, config):
    """
    Main client entry point. 
    1) Generate keys (un-benchmarked).
    2) Wrap the actual network/homomorphic ops with profile_and_monitor.
    """
    public_key, private_key = prepare_client_data(config['key_length'])

    # Build one annotation string with all relevant parameters
    annotation_str = (
        f"Client Operation | "
        f"NB_RUNS={config['nb_runs']}, "
        f"MESSAGE_SIZE={config['msg_size']}, "
        f"MESSAGE_NB={config['msg_nb']}, "
        f"KEY_LENGTH={config['key_length']}, "
        f"OPERATION={config['operation']}"
    )

    # We dynamically apply the decorator by calling profile_and_monitor(...) inside:
    benchmarked_fn = profile_and_monitor(
        number=config['nb_runs'],
        annotation=annotation_str
    )(run_client_operations)

    # Now run it
    benchmarked_fn(server_ip, config['operation'], public_key, private_key, config)


# --------------------------
# Actual server operations we want to benchmark
def run_server_operations(config):
    """
    This function is the 'core' server logic that we'll benchmark using profile_and_monitor.
    """
    # Create socket server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", get_port()))
    sock.listen(1)
    print("> Waiting for client connection...")
    
    conn, _ = sock.accept()
    print("> Receiving DataToCompute")
    data_to_compute = receive_data(conn)
    
    data_to_compute = json.loads(data_to_compute)
    operation = data_to_compute['operation']
    
    # Deserialize encrypted messages
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
            raise ValueError("Both encrypted message lists must be of same length for 'add_encrypted'.")
    else:
        raise ValueError(f"Operation {operation} not supported!")
    
    scalar = data_to_compute['scalar']
    
    # Perform the requested homomorphic operation
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
    
    # Serialize the result and send it back
    serialized_data = serialize_data(public_key, encrypted_result)
    print("> Sending result back to client")
    send_data(conn, serialized_data)
    
    conn.close()
    sock.close()

def server(config):
    """
    Main server entry point.
    We'll wrap the actual server logic with profile_and_monitor for benchmarking.
    """
    annotation_str = (
        f"Server Operation | "
        f"NB_RUNS={config['nb_runs']}, "
        f"MESSAGE_SIZE={config['msg_size']}, "
        f"MESSAGE_NB={config['msg_nb']}, "
        f"KEY_LENGTH={config['key_length']}, "
        f"OPERATION={config['operation']}"
    )

    benchmarked_fn = profile_and_monitor(
        number=config['nb_runs'],
        annotation=annotation_str
    )(run_server_operations)

    # Run it
    benchmarked_fn(config)


# --------------------------
# Main entry
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action='store_true', help="Run as server")
    parser.add_argument("--client", type=str, help="Run as client, specify server IP")
    parser.add_argument("--operation", type=str, default="add",
                        help="Operation to perform: 'add', 'add_encrypted', 'mul', 'div'")
    parser.add_argument("--nb_runs", type=int, default=2, help="Number of runs for the benchmark")
    parser.add_argument("--msg_size", type=int, default=2**10, help="Message size in bits")
    parser.add_argument("--msg_nb", type=int, default=2**2, help="Number of messages")
    parser.add_argument("--key_length", type=int, default=2**12, help="Key length in bits")
    args = parser.parse_args()

    config = {
        'nb_runs': args.nb_runs,
        'msg_size': args.msg_size,
        'msg_nb': args.msg_nb,
        'key_length': args.key_length,
        'operation': args.operation,
    }

    if args.server:
        server(config)
    elif args.client:
        client(args.client, config)
    else:
        print("Please specify either --server or --client <server_ip>, you can also --help")
        exit(1)
