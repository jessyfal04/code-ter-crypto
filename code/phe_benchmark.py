import socket
import random
import argparse
import json
import math
import struct
import time
from colorama import Fore

from phe import paillier
import benchmark
from benchmark import profile_and_monitor

# -----------------------------------------------------------
#              Constants & Global
# -----------------------------------------------------------
INITIAL_PORT = 12510  # Starting port for communication
COUNT_PORT = 0        # Counter for port allocation
BUFFER_SIZE = 4096    # Buffer size for socket reads/writes

# -----------------------------------------------------------
#              Helper for Unique Port
# -----------------------------------------------------------
def get_port():
    """
    Returns a new port for each connection to avoid
    conflicts when multiple runs happen quickly.
    """
    global COUNT_PORT
    COUNT_PORT += 1
    port = INITIAL_PORT + COUNT_PORT
    print(f"Using port: {port}")
    return port

# -----------------------------------------------------------
#              Send / Receive Data
# -----------------------------------------------------------
def send_data(sock, data):
    """
    Send data reliably in two stages:
    1) Send the length (4 bytes)
    2) Send the actual payload in BUFFER_SIZE chunks
    """
    data_bytes = data.encode('utf-8')
    data_length = len(data_bytes)
    
    # Send the length (network byte order: !I)
    sock.sendall(struct.pack('!I', data_length))
    
    # Send the actual data
    sent_bytes = 0
    while sent_bytes < data_length:
        chunk = data_bytes[sent_bytes:sent_bytes + BUFFER_SIZE]
        sock.sendall(chunk)
        sent_bytes += len(chunk)
    
    benchmark.current_network_bytes_sent += data_length

def receive_data(sock):
    """
    Receives data in two stages:
    1) Receive the 4-byte length
    2) Receive the actual data in BUFFER_SIZE chunks
    """
    raw_length = sock.recv(4)
    if not raw_length:
        return None
    data_length = struct.unpack('!I', raw_length)[0]
    
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

# -----------------------------------------------------------
#              Paillier Key/Encryption Helpers
# -----------------------------------------------------------
def generate_keypair(key_length):
    print(f"> Generating Keypair of length {key_length} bits")
    public_key, private_key = paillier.generate_paillier_keypair(n_length=key_length)
    return public_key, private_key

def encrypt_messages(public_key, messages):
    print(f"> Encrypting {len(messages)} message(s)")
    return [public_key.encrypt(m) for m in messages]

def decrypt_messages(private_key, encrypted_messages):
    print(f"> Decrypting {len(encrypted_messages)} message(s)")
    return [private_key.decrypt(m) for m in encrypted_messages]

def serialize_data(encrypted_number_list):
    """
    Convert a list of EncryptedNumber into a JSON string.
    """
    print("> Serializing encrypted data")
    enc_dict = {
        'values': [
            (str(x.ciphertext()), x.exponent) for x in encrypted_number_list
        ]
    }
    return json.dumps(enc_dict)

def deserialize_data(serialized_data, public_key):
    """
    Convert a JSON string back into a list of EncryptedNumber.
    """
    print("> Deserializing encrypted data")
    data_dict = json.loads(serialized_data)
    return [
        paillier.EncryptedNumber(public_key, int(ctxt), int(exp))
        for (ctxt, exp) in data_dict['values']
    ]

# -----------------------------------------------------------
#              Homomorphic Operations
# -----------------------------------------------------------
def add_encrypted_scalar(enc, scalar):
    return enc + scalar

def add_encrypted_numbers(enc1, enc2):
    return enc1 + enc2

def multiply_encrypted_by_scalar(enc, scalar):
    return enc * scalar

def divide_encrypted_by_scalar(enc, scalar):
    if scalar == 0:
        raise ValueError("Division by zero is not allowed.")
    return enc * (1 / scalar)

def perform_homomorphic_operation(operation, encrypted_msgs, scalar=None, encrypted_msgs2=None):
    """
    Apply the homomorphic operation to the data.
    For 'add', 'mul', 'div': needs encrypted_msgs + scalar.
    For 'add_encrypted': needs two sets of encrypted messages.
    """
    if operation == 'add':
        return [add_encrypted_scalar(m, scalar) for m in encrypted_msgs]
    elif operation == 'mul':
        return [multiply_encrypted_by_scalar(m, scalar) for m in encrypted_msgs]
    elif operation == 'div':
        return [divide_encrypted_by_scalar(m, scalar) for m in encrypted_msgs]
    elif operation == 'add_encrypted':
        return [add_encrypted_numbers(m1, m2)
                for m1, m2 in zip(encrypted_msgs, encrypted_msgs2)]
    else:
        raise ValueError(f"Unsupported operation: {operation}")

# -----------------------------------------------------------
#              Latency Measurement
# -----------------------------------------------------------
def measure_latency_client(server_ip):
    """
    Client side:
      - Connect to the server, send "ping", wait for "pingpong", then send "pong".
      - Measure round-trip latency and update benchmark.current_network_latency.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((server_ip, get_port()))
        start_time = time.time()
        send_data(sock, "ping")
        if receive_data(sock) != "pingpong":
            print("Unexpected response")
            return
        rtt_client = (time.time() - start_time) * 1000
        send_data(sock, "pong")
        print(f"[Client] RTT: {rtt_client:.2f} ms")
        benchmark.current_network_latency = rtt_client

def measure_latency_server():
    """
    Server side:
      - Accept a connection, wait for "ping" from the client, then send "pingpong".
      - Wait for "pong" from the client, measure round-trip latency, and update benchmark.current_network_latency.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", get_port()))
        sock.listen(1)
        conn, _ = sock.accept()
        with conn:
            if receive_data(conn) != "ping":
                print("Unexpected request")
                return
            start_time = time.time()
            send_data(conn, "pingpong")
            if receive_data(conn) != "pong":
                print("Unexpected reply")
                return
            rtt_server = (time.time() - start_time) * 1000
            print(f"[Server] RTT: {rtt_server:.2f} ms")
            benchmark.current_network_latency = rtt_server

# -----------------------------------------------------------
#              Public Key Exchange
# -----------------------------------------------------------
def send_public_key(server_ip, public_key):
    """
    Client sends its Paillier public key to the server.
    """
    print("> Sending Public Key to Server")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((server_ip, get_port()))
        key_data = {'public_key': {'g': public_key.g, 'n': public_key.n}}
        send_data(sock, json.dumps(key_data))
        # Could wait for an ACK if desired; here just close.

def receive_public_key():
    """
    Server receives the Paillier public key from the client.
    """
    print("> Receiving Public Key from Client")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", get_port()))
        sock.listen(1)
        conn, _ = sock.accept()
        with conn:
            data = receive_data(conn)
            public_key_dict = json.loads(data)['public_key']
            return paillier.PaillierPublicKey(n=int(public_key_dict['n']))

# -----------------------------------------------------------
#   Validate and Generate Expected Results (Client side)
# -----------------------------------------------------------
def compute_expected_result(operation, messages, scalar=None):
    """
    Create the expected (plaintext) result for 'add', 'mul', 'div' operation
    given the original plaintext messages and the scalar.
    """
    if operation == "add":
        return [m + scalar for m in messages]
    elif operation == "mul":
        return [m * scalar for m in messages]
    elif operation == "div":
        reciprocal = 1 / scalar
        return [m * reciprocal for m in messages]
    else:
        raise ValueError(f"Operation {operation} not supported for expected result computation!")

# -----------------------------------------------------------
#              Client Workflow
# -----------------------------------------------------------
def run_client_operations(server_ip, operation, public_key, private_key, config):
    """
    1) Measure latency
    2) Send public key
    3) Encrypt random data, send to server for homomorphic ops
    4) Receive result, decrypt, verify correctness
    """
    # Step 1: measure network latency
    measure_latency_client(server_ip)

    nb_messages = config['msg_nb']
    msg_size = config['msg_size']
    scalar = random.getrandbits(1024)

    # Step 3: create random messages and encrypt
    messages = [random.randrange(2**(msg_size-1), 2**msg_size) for _ in range(nb_messages)]
    encrypted_messages = encrypt_messages(public_key, messages)

    print(f"> Computing {operation} over {nb_messages} message(s)")
    data_to_compute = {
        'operation': operation,
        'scalar': scalar
    }

    # 'add_encrypted' requires a second dataset; others just need one
    if operation in ['add', 'mul', 'div']:
        data_to_compute['serialized_data'] = serialize_data(encrypted_messages)
    elif operation == 'add_encrypted':
        # Reuse the same messages for simplicity
        data_to_compute['serialized_data']  = serialize_data(encrypted_messages)
        data_to_compute['serialized_data2'] = serialize_data(encrypt_messages(public_key, messages))
    else:
        raise ValueError(f"Unsupported operation {operation} on client")

    # Connect, send data, receive processed result
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((server_ip, get_port()))
        print("> Sending data to server for computation")
        send_data(sock, json.dumps(data_to_compute))

        print("> Waiting for server result...")
        serialized_data = receive_data(sock)

    # Step 4: decrypt and verify
    encrypted_result = deserialize_data(serialized_data, public_key)
    decrypted_result = decrypt_messages(private_key, encrypted_result)

    # Check correctness
    if operation in ["add", "mul", "div"]:
        expected_result = compute_expected_result(operation, messages, scalar)
    elif operation == "add_encrypted":
        # Just do a pairwise add in plaintext
        expected_result = [m1 + m2 for (m1, m2) in zip(messages, messages)]
    else:
        raise ValueError(f"Unsupported operation {operation} for verification")

    ok = True
    for i, (dec, exp) in enumerate(zip(decrypted_result, expected_result)):
        # If it's int vs float, handle carefully:
        if isinstance(exp, int):
            if dec != exp:
                print(f"Index {i} mismatch: decrypted={dec} vs expected={exp}")
                ok = False
        else:
            # float comparison
            if not math.isclose(dec, exp, rel_tol=1e-5):
                print(f"Index {i} mismatch: decrypted={dec} not close to expected={exp}")
                ok = False

    if ok:
        print("All decrypted values match expected plaintext results!")

def client(server_ip, config, public_key, private_key):
    """
    Wrapper that runs the homomorphic operations with profiling/monitoring.
    """
    folder_prefix = config["folder_prefix"] if config["folder_prefix"] != "" else f"client_{config['operation']}_{config['msg_size']}bits"
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
        folder_prefix=folder_prefix,
        annotation=annotation_str
    )(run_client_operations)

    benchmarked_fn(server_ip, config['operation'], public_key, private_key, config)

# -----------------------------------------------------------
#              Server Workflow
# -----------------------------------------------------------
def run_server_operations(config):
    """
    1) Measure latency (server side)
    2) Receive public key from client
    3) Accept data from client, perform homomorphic op
    4) Send result back
    """
    # Step 1: measure server latency
    measure_latency_server()

    # Step 3: accept data for homomorphic computation
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", get_port()))
        sock.listen(1)
        print("> Waiting for client data...")
        conn, _ = sock.accept()
        with conn:
            data_to_compute = json.loads(receive_data(conn))
            operation = data_to_compute['operation']
            scalar = data_to_compute['scalar']

            # Deserialize
            if operation == 'add_encrypted':
                enc_msgs = deserialize_data(data_to_compute['serialized_data'], public_key)
                enc_msgs2 = deserialize_data(data_to_compute['serialized_data2'], public_key)
                if len(enc_msgs) != len(enc_msgs2):
                    raise ValueError("Both encrypted message lists must have the same length.")
                encrypted_result = perform_homomorphic_operation(
                    operation, enc_msgs, encrypted_msgs2=enc_msgs2
                )
            else:
                # add, mul, div
                enc_msgs = deserialize_data(data_to_compute['serialized_data'], public_key)
                encrypted_result = perform_homomorphic_operation(operation, enc_msgs, scalar=scalar)

            serialized_result = serialize_data(encrypted_result)
            print("> Sending homomorphic result back to client")
            send_data(conn, serialized_result)

def server(config):
    """
    Wrapper that runs the homomorphic operations with profiling/monitoring, on server side.
    """
    folder_prefix = config["folder_prefix"] if config["folder_prefix"] != "" else f"server_{config['operation']}_{config['msg_size']}bits"
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
        folder_prefix=folder_prefix,
        annotation=annotation_str
    )(run_server_operations)

    benchmarked_fn(config)

# -----------------------------------------------------------
#              Main Entry Point
# -----------------------------------------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action='store_true', help="Run as server")
    parser.add_argument("--client", type=str, help="Run as client, specify server IP")
    parser.add_argument("--operation", type=str, default="add",
                        help="Operation(s): 'add', 'add_encrypted', 'mul', 'div', 'all' or comma-separated list.")
    parser.add_argument("--nb_runs", type=int, default=2, help="Number of runs for the benchmark")
    parser.add_argument("--msg_size", type=str, default="1024",
                        help="Message size in bits. Can be an integer or comma-separated exponent list (e.g. '2,4,6').")
    parser.add_argument("--msg_nb", type=str, default="4",
                        help="Number of messages. Can be an integer or comma-separated exponent list (e.g. '2,4,6').")
    parser.add_argument("--key_length", type=int, default=4096, help="Paillier key length in bits")
    parser.add_argument("--folder_prefix", type=str, default="", help="Folder name for results")
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

    # Decide how many messages to run
    if ',' in args.msg_nb:
        msg_nb_list = [2 ** int(x.strip()) for x in args.msg_nb.split(',')]
    else:
        msg_nb_list = [int(args.msg_nb)]

    # If client, prepare once for all runs
    public_key, private_key = None, None
    if args.client:
        public_key, private_key = generate_keypair(args.key_length)
        send_public_key(args.client, public_key)
    else:
        public_key = receive_public_key()
    print("Press Enter to start the benchmark.")
    input()

    # Nested loops over different combinations
    for nb in msg_nb_list:
        for ms in msg_size_list:
            for op in operations:
                config = {
                    'nb_runs': args.nb_runs,
                    'msg_size': ms,
                    'msg_nb': nb,
                    'key_length': args.key_length,
                    'operation': op,
                    'folder_prefix': args.folder_prefix
                }

                # Display config
                print(Fore.YELLOW)
                print("Configuration:")
                for k, v in config.items():
                    print(f"  {k}: {v}")
                print(Fore.RESET)

                if args.server:
                    server(config)
                elif args.client:
                    client(args.client, config, public_key, private_key)
                else:
                    print("Please specify either --server or --client <server_ip>. See --help.")
                    exit(1)
