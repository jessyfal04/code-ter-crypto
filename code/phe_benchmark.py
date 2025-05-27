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

INITIAL_PORT = 12513
COUNT_PORT = 0
BUFFER_SIZE = 4096

def get_port():
    global COUNT_PORT
    COUNT_PORT += 1
    port = INITIAL_PORT + COUNT_PORT
    print(f"Using port: {port}")
    return port

benchmark.current_network_bytes_sent = 0
benchmark.current_network_bytes_received = 0
benchmark.current_network_latency = 0

def send_data(sock, data):
    data_bytes = data.encode('utf-8')
    data_length = len(data_bytes)
    
    sock.sendall(struct.pack('!I', data_length))
    
    sent_bytes = 0
    while sent_bytes < data_length:
        chunk = data_bytes[sent_bytes:sent_bytes + BUFFER_SIZE]
        sock.sendall(chunk)
        sent_bytes += len(chunk)
    
    benchmark.current_network_bytes_sent += data_length

def receive_data(sock):
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

def generate_keypair(key_length):
    print(f"> Generating Keypair of length {key_length} bits")
    public_key, private_key = paillier.generate_paillier_keypair(n_length=key_length)
    return public_key, private_key

def encrypt_messages(public_key, messages):
    print(f"> Encrypting {len(messages)} value(s)")
    return [public_key.encrypt(m) for m in messages]

def decrypt_messages(private_key, encrypted_messages):
    print(f"> Decrypting {len(encrypted_messages)} value(s)")
    return [private_key.decrypt(m) for m in encrypted_messages]

def serialize_encrypted_data(encrypted_number_list):
    print("> Serializing encrypted data")
    enc_dict = {
        'values': [
            (str(x.ciphertext()), x.exponent) for x in encrypted_number_list
        ]
    }
    return json.dumps(enc_dict)

def deserialize_encrypted_data(serialized_data, public_key):
    print("> Deserializing encrypted data")
    data_dict = json.loads(serialized_data)
    return [
        paillier.EncryptedNumber(public_key, int(ctxt), int(exp))
        for (ctxt, exp) in data_dict['values']
    ]

def serialize_plain_data(plain_list):
    print("> Serializing plaintext data")
    return json.dumps({'values': plain_list})

def deserialize_plain_data(serialized_data):
    print("> Deserializing plaintext data")
    data_dict = json.loads(serialized_data)
    return data_dict['values']

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

def perform_homomorphic_operation(operation, data_list, scalar=None, data_list2=None):
    print("> Performing Homomorphic Operation:", operation)
    if operation == 'add':
        return [add_encrypted_scalar(m, scalar) for m in data_list]
    elif operation == 'mul':
        return [multiply_encrypted_by_scalar(m, scalar) for m in data_list]
    elif operation == 'div':
        return [divide_encrypted_by_scalar(m, scalar) for m in data_list]
    elif operation == 'add_encrypted':
        return [add_encrypted_numbers(m1, m2)
                for m1, m2 in zip(data_list, data_list2)]
    else:
        raise ValueError(f"Unsupported operation: {operation}")

def compute_expected_result(operation, messages, scalar=None):
    if operation == "add":
        return [m + scalar for m in messages]
    elif operation == "mul":
        return [m * scalar for m in messages]
    elif operation == "div":
        reciprocal = 1 / scalar
        return [m * reciprocal for m in messages]
    elif operation == "add_encrypted":
        # This is used if we're adding the same set of messages to itself
        raise ValueError("For add_encrypted, the caller should do its own expected calc.")
    else:
        raise ValueError(f"Operation {operation} not supported for expected result computation!")

########################################################################
# Utility functions to generate, flatten, and unflatten mock medical data
########################################################################
def generate_mock_medical_data(num_patients, num_vitals):
    """
    Generate a list of mock medical data. Each 'patient' has
    a list of random integer vital signs.
    """
    medical_data = []
    for p_id in range(num_patients):
        # For example, random 'vitals' from 60 to 120
        vitals = [random.randint(60, 120) for _ in range(num_vitals)]
        # Store (patient_id, list_of_vitals)
        medical_data.append((p_id + 1, vitals))
    return medical_data

def flatten_medical_data(medical_data):
    """
    Flatten mock medical data (list of (patient_id, [vitals])) 
    into a single list of integers for encryption/operations.
    """
    flattened = []
    for p_id, vitals in medical_data:
        flattened.extend(vitals)
    return flattened

def unflatten_medical_data(flattened_data, num_patients, num_vitals):
    """
    Reconstruct the (patient_id, [vitals]) structure
    from a single flat list, assuming the same shape
    (num_patients x num_vitals).
    """
    medical_data = []
    idx = 0
    for p_id in range(num_patients):
        vitals = flattened_data[idx : idx + num_vitals]
        medical_data.append((p_id + 1, vitals))
        idx += num_vitals
    return medical_data

########################################################################
# Latency measurement
########################################################################
def measure_latency_client(sock):
    start_time = time.time()
    send_data(sock, "ping")
    if receive_data(sock) != "pingpong":
        print("Unexpected response")
        return
    rtt_client = (time.time() - start_time) * 1000
    send_data(sock, "pong")
    print(f"[Client] RTT: {rtt_client:.2f} ms")
    benchmark.current_network_latency = rtt_client

def measure_latency_server(conn):
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

########################################################################
# Key exchange
########################################################################
def send_public_key(sock, public_key):
    print("> Sending Public Key to Server")
    key_data = {'public_key': {'g': public_key.g, 'n': public_key.n}}
    send_data(sock, json.dumps(key_data))

def receive_public_key(conn):
    print("> Receiving Public Key from Client")
    data = receive_data(conn)
    public_key_dict = json.loads(data)['public_key']
    return paillier.PaillierPublicKey(n=int(public_key_dict['n']))

########################################################################
# Client workflow for a single operation
########################################################################
def run_client_operations(sock, operation, public_key, private_key, config):
    use_phe = config['use_phe']

    # We'll interpret msg_nb as the number of patients
    # and msg_size as the number of vitals per patient.
    nb_patients = config['msg_nb']
    nb_vitals_per_patient = config['msg_size']

    # Instead of random big integer messages, generate mock medical data
    medical_data = generate_mock_medical_data(nb_patients, nb_vitals_per_patient)
    # Flatten medical data so we can encrypt it easily
    flattened_data = flatten_medical_data(medical_data)

    # We'll choose a random scalar for operations like 'add', 'mul', 'div'
    scalar = random.getrandbits(1024)

    if use_phe:
        encrypted_data = encrypt_messages(public_key, flattened_data)
        print(f"> Computing {operation} on {nb_patients} patients (each with {nb_vitals_per_patient} vitals) with PHE")
    else:
        encrypted_data = flattened_data
        print(f"> Computing {operation} on {nb_patients} patients (each with {nb_vitals_per_patient} vitals) in plaintext mode")

    data_to_compute = {
        'operation': operation,
        'scalar': scalar,
        'use_phe': use_phe
    }

    if operation in ['add', 'mul', 'div']:
        if use_phe:
            data_to_compute['serialized_data'] = serialize_encrypted_data(encrypted_data)
        else:
            data_to_compute['serialized_data'] = serialize_plain_data(encrypted_data)
    elif operation == 'add_encrypted':
        # We'll do a demonstration by "adding" the same flattened_data to itself
        # in an encrypted manner
        if use_phe:
            data_to_compute['serialized_data']  = serialize_encrypted_data(encrypted_data)
            data_to_compute['serialized_data2'] = serialize_encrypted_data(encrypt_messages(public_key, flattened_data))
        else:
            data_to_compute['serialized_data']  = serialize_plain_data(encrypted_data)
            data_to_compute['serialized_data2'] = serialize_plain_data(flattened_data)
    else:
        raise ValueError(f"Unsupported operation {operation} on client")

    print("> Sending data to server for computation")
    send_data(sock, json.dumps(data_to_compute))

    print("> Waiting for server result...")
    serialized_data = receive_data(sock)

    if use_phe:
        encrypted_result = deserialize_encrypted_data(serialized_data, public_key)
        decrypted_result = decrypt_messages(private_key, encrypted_result)
    else:
        decrypted_result = deserialize_plain_data(serialized_data)

    # For verification, compute expected result in plaintext
    if operation in ["add", "mul", "div"]:
        expected_result = compute_expected_result(operation, flattened_data, scalar)
    elif operation == "add_encrypted":
        # This means: each vital gets added to itself =>  vital + vital
        expected_result = [m1 + m2 for (m1, m2) in zip(flattened_data, flattened_data)]
    else:
        raise ValueError(f"Unsupported operation {operation} for verification")

    # Check correctness
    ok = True
    for i, (dec, exp) in enumerate(zip(decrypted_result, expected_result)):
        # If it's an integer-based operation, check equality
        if isinstance(exp, int):
            if dec != exp:
                print(f"Index {i} mismatch: result={dec} vs expected={exp}")
                ok = False
        else:
            # If it's float-based (from division), use isclose
            if not math.isclose(dec, exp, rel_tol=1e-5):
                print(f"Index {i} mismatch: result={dec} not close to expected={exp}")
                ok = False

    if ok:
        print("All computed values match expected plaintext results!")
    else:
        print("Some differences were found in the homomorphic results.")

def client(sock, config, public_key, private_key):
    folder_prefix = config["folder_prefix"] if config["folder_prefix"] != "" else f"client_{config['operation']}_{config['msg_size']}bits"
    annotation_str = (
        f"Client Operation | "
        f"NB_RUNS={config['nb_runs']}, "
        f"MESSAGE_SIZE={config['msg_size']}, "
        f"MESSAGE_NB={config['msg_nb']}, "
        f"KEY_LENGTH={config['key_length']}, "
        f"OPERATION={config['operation']}, "
        f"USE_PHE={config['use_phe']}"
    )

    benchmarked_fn = profile_and_monitor(
        number=config['nb_runs'],
        folder_prefix=folder_prefix,
        annotation=annotation_str
    )(run_client_operations)

    # Pass the same sock each time
    benchmarked_fn(sock, config['operation'], public_key, private_key, config)

########################################################################
# Server workflow
########################################################################
def run_server_operations(conn, config, public_key):
    use_phe = config['use_phe']

    print("> Waiting for client data...")
    data_to_compute = json.loads(receive_data(conn))
    operation = data_to_compute['operation']
    scalar = data_to_compute['scalar']
    client_use_phe = data_to_compute['use_phe']

    if client_use_phe != use_phe:
        print("Warning: Client's use_phe != Server's use_phe. Results may be inconsistent.")

    if operation == 'add_encrypted':
        if use_phe:
            enc_msgs  = deserialize_encrypted_data(data_to_compute['serialized_data'],  public_key)
            enc_msgs2 = deserialize_encrypted_data(data_to_compute['serialized_data2'], public_key)
        else:
            enc_msgs  = deserialize_plain_data(data_to_compute['serialized_data'])
            enc_msgs2 = deserialize_plain_data(data_to_compute['serialized_data2'])

        if len(enc_msgs) != len(enc_msgs2):
            raise ValueError("Both lists must have the same length.")

        result = perform_homomorphic_operation(operation, enc_msgs, data_list2=enc_msgs2)
    else:
        if use_phe:
            enc_msgs = deserialize_encrypted_data(data_to_compute['serialized_data'], public_key)
        else:
            enc_msgs = deserialize_plain_data(data_to_compute['serialized_data'])

        result = perform_homomorphic_operation(operation, enc_msgs, scalar=scalar)

    if use_phe:
        serialized_result = serialize_encrypted_data(result)
    else:
        serialized_result = serialize_plain_data(result)

    print("> Sending computation result back to client")
    send_data(conn, serialized_result)

def server(conn, config, public_key):
    folder_prefix = config["folder_prefix"] if config["folder_prefix"] != "" else f"server_{config['operation']}_{config['msg_size']}bits"
    annotation_str = (
        f"Server Operation | "
        f"NB_RUNS={config['nb_runs']}, "
        f"MESSAGE_SIZE={config['msg_size']}, "
        f"MESSAGE_NB={config['msg_nb']}, "
        f"KEY_LENGTH={config['key_length']}, "
        f"OPERATION={config['operation']}, "
        f"USE_PHE={config['use_phe']}"
    )

    benchmarked_fn = profile_and_monitor(
        number=config['nb_runs'],
        folder_prefix=folder_prefix,
        annotation=annotation_str
    )(run_server_operations)

    benchmarked_fn(conn, config, public_key)

#####################################################################
# Main
#####################################################################
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action='store_true', help="Run as server")
    parser.add_argument("--client", type=str, help="Run as client, specify server IP")
    parser.add_argument("--operation", type=str, default="add",
                        help="Operation(s): 'add', 'add_encrypted', 'mul', 'div', 'all' or comma-separated list.")
    parser.add_argument("--nb_runs", type=int, default=2, help="Number of runs for the benchmark")
    parser.add_argument("--msg_size", type=str, default="1024",
                        help="Interpreted now as the 'number of vitals' per patient (integer or comma-separated).")
    parser.add_argument("--msg_nb", type=str, default="4",
                        help="Interpreted now as the 'number of patients' (integer or comma-separated).")
    parser.add_argument("--key_length", type=int, default=4096, help="Paillier key length in bits")
    parser.add_argument("--folder_prefix", type=str, default="", help="Folder name for results")
    parser.add_argument("--use_phe", type=lambda x: x.lower() == 'true', default=True,
                        help="Use Paillier-based encryption if True, else plaintext. (Default: True)")

    args = parser.parse_args()
    use_phe = args.use_phe

    if args.operation == 'all':
        operations = ['add', 'add_encrypted', 'mul', 'div']
    elif ',' in args.operation:
        operations = [x.strip() for x in args.operation.split(',')]
    else:
        operations = [args.operation]

    if ',' in args.msg_size:
        msg_size_list = [int(x.strip()) for x in args.msg_size.split(',')]
    else:
        msg_size_list = [int(args.msg_size)]

    if ',' in args.msg_nb:
        msg_nb_list = [int(x.strip()) for x in args.msg_nb.split(',')]
    else:
        msg_nb_list = [int(args.msg_nb)]

    public_key, private_key = None, None

    ####################################################################
    # SERVER mode
    ####################################################################
    if args.server:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        main_port = get_port()
        server_sock.bind(("0.0.0.0", main_port))
        server_sock.listen(1)
        print(f"Server listening on port {main_port}")
        conn, addr = server_sock.accept()
        print(f"Server accepted connection from {addr}")

        if use_phe:
            public_key = receive_public_key(conn)

        measure_latency_server(conn)

        print("Press Enter to start the benchmark.")
        input()

        for nb in msg_nb_list:
            for ms in msg_size_list:
                for op in operations:
                    benchmark.current_network_bytes_sent = 0
                    benchmark.current_network_bytes_received = 0
                    config = {
                        'nb_runs': args.nb_runs,
                        'msg_size': ms,   # number of vitals
                        'msg_nb': nb,     # number of patients
                        'key_length': args.key_length,
                        'operation': op,
                        'folder_prefix': args.folder_prefix,
                        'use_phe': use_phe
                    }

                    print(Fore.YELLOW)
                    print("Configuration:")
                    for k, v in config.items():
                        print(f"  {k}: {v}")
                    print(Fore.RESET)

                    server(conn, config, public_key)

        conn.close()
        server_sock.close()

    ####################################################################
    # CLIENT mode
    ####################################################################
    elif args.client:
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        main_port = get_port()
        client_sock.connect((args.client, main_port))
        print(f"Client connected to {args.client}:{main_port}")

        if use_phe:
            public_key, private_key = generate_keypair(args.key_length)
            send_public_key(client_sock, public_key)

        measure_latency_client(client_sock)

        print("Press Enter to start the benchmark.")
        input()

        for nb in msg_nb_list:
            for ms in msg_size_list:
                for op in operations:
                    benchmark.current_network_bytes_sent = 0
                    benchmark.current_network_bytes_received = 0
                    config = {
                        'nb_runs': args.nb_runs,
                        'msg_size': ms,   # number of vitals
                        'msg_nb': nb,     # number of patients
                        'key_length': args.key_length,
                        'operation': op,
                        'folder_prefix': args.folder_prefix,
                        'use_phe': use_phe
                    }

                    print(Fore.YELLOW)
                    print("Configuration:")
                    for k, v in config.items():
                        print(f"  {k}: {v}")
                    print(Fore.RESET)

                    client(client_sock, config, public_key, private_key)

        client_sock.close()

    else:
        print("Please specify either --server or --client <server_ip>. See --help.")
