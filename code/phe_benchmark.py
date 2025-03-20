import socket
import random
import argparse
import json
import math
import struct

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
INITIAL_PORT = 12500  # Port for communication
COUNT_PORT = 0  # Counter for port allocation
BUFFER_SIZE = 4096  # Reduced buffer size for safer memory usage

def get_port():
    global COUNT_PORT
    COUNT_PORT += 1
    print(f"Port: {INITIAL_PORT + COUNT_PORT}")
    return INITIAL_PORT + COUNT_PORT

def send_data(sock, data):
    data_bytes = data.encode('utf-8')
    data_length = len(data_bytes)
    
    # Send the length of the data first
    sock.sendall(struct.pack('!I', data_length))
    
    # Send the actual data in chunks
    sent_bytes = 0
    while sent_bytes < data_length:
        chunk = data_bytes[sent_bytes:sent_bytes + BUFFER_SIZE]
        sock.sendall(chunk)
        sent_bytes += len(chunk)
    
    benchmark.current_network_bytes_sent += data_length

def receive_data(sock):
    # Receive the length of the data first
    raw_length = sock.recv(4)
    if not raw_length:
        return None
    data_length = struct.unpack('!I', raw_length)[0]
    
    # Receive the actual data in chunks
    received_bytes = 0
    data_chunks = []
    while received_bytes < data_length:
        chunk = sock.recv(min(BUFFER_SIZE, data_length - received_bytes))
        if not chunk:
            break
        data_chunks.append(chunk)
        received_bytes += len(chunk)
    
    data = b''.join(data_chunks).decode('utf-8')
    benchmark.current_network_bytes_received += received_bytes
    return data

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

def prepare_client_data(key_length):
    """
    Prepares client data (key generation) outside of the benchmarked section.
    """
    public_key, private_key = generate_keypair(key_length)
    return public_key, private_key

# --------------------------
# Actual client operations
def run_client_operations(server_ip, operation, public_key, private_key, config):
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
    
    # Deserialize the result
    _, encrypted_result = deserialize_data(serialized_data)
    decrypted_result = decrypt_messages(private_key, encrypted_result)

    # Check correctness
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
    
    ok = True
    for i, (dec, exp) in enumerate(zip(decrypted_result, expected_result)):
        # If it's int vs float, handle carefully:
        if isinstance(exp, int):
            if dec != exp:
                print(f"{i} Decrypted value {dec} != expected {exp}")
                ok = False
        else:
            if not math.isclose(dec, exp, rel_tol=1e-5):
                print(f"{i} Decrypted value {dec} not close to expected {exp}")
                ok = False

    if ok:
        print("All decrypted values match expected values")

def client(server_ip, config, public_key, private_key):
    """
    Main client entry point.
    1) Generate keys (un-benchmarked).
    2) Wrap the actual network/homomorphic ops in profile_and_monitor.
    """
    folder_prexix = f"client_{config['operation']}_{config['msg_size']}bits"

    annotation_str = (
        f"Client Operation | "
        f"NB_RUNS={config['nb_runs']}, "
        f"MESSAGE_SIZE={config['msg_size']}, "
        f"MESSAGE_NB={config['msg_nb']}, "
        f"KEY_LENGTH={config['key_length']}, "
        f"OPERATION={config['operation']}"
    )

    benchmarked_fn = profile_and_monitor(
        number=config['nb_runs'],
        folder_prefix=folder_prexix,
        annotation=annotation_str
    )(run_client_operations)

    benchmarked_fn(server_ip, config['operation'], public_key, private_key, config)


# --------------------------
# Actual server operations
def run_server_operations(config):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", get_port()))
    sock.listen(1)
    print("> Waiting for client connection...")
    
    conn, _ = sock.accept()
    print("> Receiving DataToCompute")
    data_to_compute = receive_data(conn)
    
    data_to_compute = json.loads(data_to_compute)
    operation = data_to_compute['operation']
    
    # Deserialize
    if operation in ['add', 'mul', 'div']:
        serialized_data = data_to_compute['serialized_data']
        public_key, encrypted_messages = deserialize_data(serialized_data)
    elif operation == 'add_encrypted':
        serialized_data = data_to_compute['serialized_data']
        serialized_data2 = data_to_compute.get('serialized_data2')
        if not serialized_data2:
            raise ValueError("Operation 'add_encrypted' requires a second data set.")
        public_key, encrypted_messages = deserialize_data(serialized_data)
        _, encrypted_messages2 = deserialize_data(serialized_data2)
        if len(encrypted_messages) != len(encrypted_messages2):
            raise ValueError("Both encrypted message lists must have same length.")
    else:
        raise ValueError(f"Operation {operation} not supported!")
    
    scalar = data_to_compute['scalar']
    
    print("> Performing Homomorphic Operations")
    if operation == 'add':
        encrypted_result = [add_encrypted_scalar(msg, scalar) for msg in encrypted_messages]
    elif operation == 'add_encrypted':
        encrypted_result = [add_encrypted_numbers(msg1, msg2)
                            for msg1, msg2 in zip(encrypted_messages, encrypted_messages2)]
    elif operation == 'mul':
        encrypted_result = [multiply_encrypted_by_scalar(msg, scalar) for msg in encrypted_messages]
    elif operation == 'div':
        encrypted_result = [divide_encrypted_by_scalar(msg, scalar) for msg in encrypted_messages]
    else:
        raise ValueError(f"Operation {operation} not supported!")
    
    serialized_data = serialize_data(public_key, encrypted_result)
    print("> Sending result back to client")
    send_data(conn, serialized_data)
    
    conn.close()
    sock.close()

def server(config):
    folder_prexix = f"server_{config['operation']}_{config['msg_size']}bits"
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
        folder_prefix=folder_prexix,
        annotation=annotation_str
    )(run_server_operations)

    benchmarked_fn(config)

# --------------------------
# Main entry
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action='store_true', help="Run as server")
    parser.add_argument("--client", type=str, help="Run as client, specify server IP")
    parser.add_argument("--operation", type=str, default="add",
                        help="Operation: 'add', 'add_encrypted', 'mul', 'div', or 'all'. Can be a comma-separated list")
    parser.add_argument("--nb_runs", type=int, default=2, help="Number of runs for the benchmark")
    parser.add_argument("--msg_size", type=str, default="1024",
                        help="Message size in bits. Can be a single integer of bits or comma-separated list of exponent of 2 min max, e.g. '2,4,6,8,10'")
    parser.add_argument("--msg_nb", type=int, default=4, help="Number of messages")
    parser.add_argument("--key_length", type=int, default=4096, help="Key length in bits")
    args = parser.parse_args()

    # Decide which operations to run
    if args.operation == 'all':
        operations = ['add', 'add_encrypted', 'mul', 'div']
    elif ',' in args.operation:
        operations = [x.strip() for x in args.operation.split(',')]
    else:
        operations = [args.operation]

    # Decide which message sizes to run
    if ',' in args.msg_size:
        msg_size_list = [2 ** int(x.strip()) for x in args.msg_size.split(',')]
    else:
        msg_size_list = [int(args.msg_size)]

    # If client, prepare the client data
    public_key, private_key = None, None
    if args.client:
        public_key, private_key = prepare_client_data(args.key_length)

    # We will run each combination of operation and msg_size
    for ms in msg_size_list:
        for op in operations:
            config = {
                'nb_runs': args.nb_runs,
                'msg_size': ms,
                'msg_nb': args.msg_nb,
                'key_length': args.key_length,
                'operation': op,
            }

            if args.server:
                server(config)
            elif args.client:
                client(args.client, config, public_key, private_key)
            else:
                print("Please specify either --server or --client <server_ip>; see --help.")
                exit(1)
