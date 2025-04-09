import socket
import random
import argparse
import json
import struct
import time
from colorama import Fore
import itertools
from abc import ABC, abstractmethod

#NOTE HE LIBRARY
from phe import paillier
import tenseal as ts
from concrete import fhe

#NOTE BENCHMARK LIBRARY
import benchmark
from benchmark import profile_and_monitor

#NOTE CONSTANTS
BUFFER_SIZE = 4096

benchmark.current_network_bytes_sent = 0
benchmark.current_network_bytes_received = 0
benchmark.current_network_latency = 0

#SECTION - HE SCHEMES
class HEScheme(ABC):
    """Abstract base class for homomorphic encryption schemes"""
    
    @abstractmethod
    def generate_keypair(self, key_length):
        """Generate a keypair for the scheme"""
        pass
    
    @abstractmethod
    def encrypt(self, public_key, message):
        """Encrypt a message"""
        pass
    
    @abstractmethod
    def decrypt(self, private_key, encrypted_message):
        """Decrypt an encrypted message"""
        pass
    
    @abstractmethod
    def serialize_encrypted(self, encrypted_number_list):
        """Serialize encrypted data"""
        pass
    
    @abstractmethod
    def deserialize_encrypted(self, serialized_data, public_key):
        """Deserialize encrypted data"""
        pass
    
    @abstractmethod
    def add_scalar(self, enc, scalar):
        """Add a scalar to an encrypted number"""
        pass
    
    @abstractmethod
    def add_encrypted(self, enc1, enc2):
        """Add two encrypted numbers"""
        pass
    
    @abstractmethod
    def multiply_scalar(self, enc, scalar):
        """Multiply an encrypted number by a scalar"""
        pass
    
    @abstractmethod
    def divide_scalar(self, enc, scalar):
        """Divide an encrypted number by a scalar"""
        pass
    
    @abstractmethod
    def serialize_public_key(self, public_key):
        """Serialize public key"""
        pass
    
    @abstractmethod
    def deserialize_public_key(self, serialized_key):
        """Deserialize public key"""
        pass

class PaillierScheme(HEScheme):
    """Paillier homomorphic encryption scheme implementation"""
    
    def generate_keypair(self, key_length):
        """Generate a Paillier keypair with optimized parameters"""
        print(f"> Generating Keypair of length {key_length} bits")
        return paillier.generate_paillier_keypair(n_length=key_length)
    
    def encrypt(self, public_key, message):
        """Encrypt a message using Paillier"""
        return public_key.encrypt(message)
    
    def decrypt(self, private_key, encrypted_message):
        """Decrypt an encrypted message using Paillier"""
        return private_key.decrypt(encrypted_message)
    
    def serialize_encrypted(self, encrypted_number_list):
        """Serialize encrypted data for Paillier"""
        print("> Serializing encrypted data")
        enc_dict = {
            'values': [
                (str(x.ciphertext()), x.exponent) for x in encrypted_number_list
            ]
        }
        return json.dumps(enc_dict)
    
    def deserialize_encrypted(self, serialized_data, public_key):
        """Deserialize encrypted data for Paillier"""
        print("> Deserializing encrypted data")
        data_dict = json.loads(serialized_data)
        return [
            paillier.EncryptedNumber(public_key, int(ctxt), int(exp))
            for (ctxt, exp) in data_dict['values']
        ]
    
    def add_scalar(self, enc, scalar):
        """Add a scalar to an encrypted number using Paillier"""
        return enc + scalar
    
    def add_encrypted(self, enc1, enc2):
        """Add two encrypted numbers using Paillier"""
        return enc1 + enc2
    
    def multiply_scalar(self, enc, scalar):
        """Multiply an encrypted number by a scalar using Paillier"""
        return enc * scalar
    
    def divide_scalar(self, enc, scalar):
        """Divide an encrypted number by a scalar using Paillier"""
        if scalar == 0:
            raise ValueError("Division by zero is not allowed.")
        return enc * (1 / scalar)
    
    def serialize_public_key(self, public_key):
        """Serialize Paillier public key"""
        return {'public_key': {'g': public_key.g, 'n': public_key.n}}
    
    def deserialize_public_key(self, serialized_key):
        """Deserialize Paillier public key"""
        public_key_dict = json.loads(serialized_key)['public_key']
        return paillier.PaillierPublicKey(n=int(public_key_dict['n']))

# Dictionary of available schemes
SCHEMES = {
    'paillier': PaillierScheme()
}
#!SECTION - END HE SCHEMES

#SECTION - NETWORKING
#ANCHOR - CONSTANTS
def create_socket():
    """Create and configure a socket with optimized settings"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock

#ANCHOR - SENDING 
def send_data(sock, data):
    """Send data efficiently"""
    data_bytes = data.encode('utf-8')
    data_length = len(data_bytes)
    
    sock.sendall(struct.pack('!I', data_length))
    
    sent_bytes = 0
    while sent_bytes < data_length:
        chunk = data_bytes[sent_bytes:sent_bytes + BUFFER_SIZE]
        sock.sendall(chunk)
        sent_bytes += len(chunk)
    
    benchmark.current_network_bytes_sent += data_length

#ANCHOR - RECEIVING
def receive_data(sock):
    """Receive data efficiently"""
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
#!SECTION - END NETWORKING

#SECTION - ENCRYPTION
#ANCHOR - KEY EXCHANGE
def generate_keypair(scheme, key_length):
    """Generate a keypair with optimized parameters"""
    return scheme.generate_keypair(key_length)

#ANCHOR - ENCRYPT
def encrypt_messages(scheme, public_key, messages):
    """Encrypt a list of messages efficiently"""
    print(f"> Encrypting {len(messages)} value(s)")
    return [scheme.encrypt(public_key, m) for m in messages]

#ANCHOR - DECRYPT
def decrypt_messages(scheme, private_key, encrypted_messages):
    """Decrypt a list of messages efficiently"""
    print(f"> Decrypting {len(encrypted_messages)} value(s)")
    return [scheme.decrypt(private_key, m) for m in encrypted_messages]
#!SECTION - END ENCRYPTION

#SECTION - SERIALIZATION
#ANCHOR - SERIALIZE
def serialize_encrypted_data(scheme, encrypted_number_list):
    """Serialize encrypted data efficiently"""
    return scheme.serialize_encrypted(encrypted_number_list)

#ANCHOR - DESERIALIZE
def deserialize_encrypted_data(scheme, serialized_data, public_key):
    """Deserialize encrypted data efficiently"""
    return scheme.deserialize_encrypted(serialized_data, public_key)
#!SECTION - END SERIALIZATION

#SECTION - HOMOMORPHIC OPERATIONS
#ANCHOR - ADD SCALAR
def add_encrypted_scalar(scheme, enc, scalar):
    """Add a scalar to an encrypted number"""
    return scheme.add_scalar(enc, scalar)

#ANCHOR - ADD ENCRYPTED
def add_encrypted_numbers(scheme, enc1, enc2):
    """Add two encrypted numbers"""
    return scheme.add_encrypted(enc1, enc2)

#ANCHOR - MULTIPLY SCALAR
def multiply_encrypted_by_scalar(scheme, enc, scalar):
    """Multiply an encrypted number by a scalar"""
    return scheme.multiply_scalar(enc, scalar)

#ANCHOR - DIVIDE SCALAR
def divide_encrypted_by_scalar(scheme, enc, scalar):
    """Divide an encrypted number by a scalar"""
    return scheme.divide_scalar(enc, scalar)

#ANCHOR - PERFORM OPERATION
def perform_homomorphic_operation(scheme, operation, data_list, scalar=None, data_list2=None, nb_operations=1):
    """Perform homomorphic operations efficiently"""
    print(f"> Performing {nb_operations} Homomorphic Operation(s): {operation}")
    
    result = data_list
    for i in range(nb_operations):
        if operation == 'add':
            result = [add_encrypted_scalar(scheme, m, scalar) for m in result]
        elif operation == 'mul':
            result = [multiply_encrypted_by_scalar(scheme, m, scalar) for m in result]
        elif operation == 'div':
            result = [divide_encrypted_by_scalar(scheme, m, scalar) for m in result]
        elif operation == 'add_encrypted':
            if len(result) != len(data_list2):
                raise ValueError("Both lists must have the same length.")
            result = [add_encrypted_numbers(scheme, m1, m2) for m1, m2 in zip(result, data_list2)]
        else:
            raise ValueError(f"Unsupported operation: {operation}")
        print(f"  Operation {i+1}/{nb_operations} completed")
    
    return result
#!SECTION - END HOMOMORPHIC OPERATIONS

#SECTION - KEY EXCHANGE
#ANCHOR - SEND KEY
def send_public_key(sock, scheme, public_key):
    """Send public key efficiently"""
    print("> Sending Public Key to Server")
    key_data = scheme.serialize_public_key(public_key)
    send_data(sock, json.dumps(key_data))

#ANCHOR - RECEIVE KEY
def receive_public_key(sock, scheme):
    """Receive public key efficiently"""
    print("> Receiving Public Key from Client")
    data = receive_data(sock)
    return scheme.deserialize_public_key(data)
#!SECTION - END KEY EXCHANGE

#SECTION - MEDICAL DATA
#ANCHOR - GENERATE MOCK
def generate_mock_medical_data(num_patients, num_vitals):
    """Generate mock medical data efficiently"""
    return [
        (p_id + 1, [random.randint(60, 120) for _ in range(num_vitals)])
        for p_id in range(num_patients)
    ]

#ANCHOR - FLATTEN
def flatten_medical_data(medical_data):
    """Flatten medical data efficiently"""
    return [vital for _, vitals in medical_data for vital in vitals]

#ANCHOR - UNFLATTEN
def unflatten_medical_data(flattened_data, num_patients, num_vitals):
    """Unflatten medical data efficiently"""
    return [
        (p_id + 1, flattened_data[p_id * num_vitals : (p_id + 1) * num_vitals])
        for p_id in range(num_patients)
    ]
#!SECTION - END MEDICAL DATA

#SECTION - LATENCY
#ANCHOR - MEASURE CLIENT
def measure_latency_client(sock):
    """Measure network latency from client side"""
    # Check readyness of the server
    send_data(sock, "ping_ready")
    if receive_data(sock) != "pong_ready":
        print("Unexpected response")
        return

    # Start RTT of the client
    start_time = time.time()
    send_data(sock, "ping")
    if receive_data(sock) != "pong":
        print("Unexpected response")
        return
    end_time = time.time()
    
    # Store the RTT and Send the RTT to the server
    rtt_client = (end_time - start_time) * 1000
    print(f"[Client] RTT: {rtt_client:.2f} ms")
    benchmark.current_network_latency = rtt_client
    send_data(sock, str(rtt_client))

#ANCHOR - MEASURE SERVER
def measure_latency_server(sock):
    """Measure network latency from server side"""
    # Validate readyness of the server
    if receive_data(sock) != "ping_ready":
        print("Unexpected response")
        return
    send_data(sock, "pong_ready")

    # Start RTT of the client
    if receive_data(sock) != "ping":
        print("Unexpected request")
        return
    send_data(sock, "pong")

    # Get the RTT of client
    rtt_server = float(receive_data(sock))

    # Store the RTT
    print(f"[Server] RTT: {rtt_server:.2f} ms")
    benchmark.current_network_latency = rtt_server
#!SECTION - END LATENCY

#SECTION - CLIENT WORKFLOW
#ANCHOR - RUN OPERATIONS
def run_client_operations(sock, scheme, operation, public_key, private_key, config):
    """Run client operations efficiently"""
    measure_latency_client(sock)

    nb_patients = config['nb_patients']
    nb_vitals = config['nb_vitals']

    # Generate and process medical data
    medical_data = generate_mock_medical_data(nb_patients, nb_vitals)
    flattened_data = flatten_medical_data(medical_data)
    scalar = random.getrandbits(1024)

    # Encrypt data
    encrypted_data = encrypt_messages(scheme, public_key, flattened_data)
    print(f"> Computing {operation} on {nb_patients} patients (each with {nb_vitals} vitals)")

    # Prepare data for computation
    data_to_compute = {
        'operation': operation,
        'scalar': scalar,
        'serialized_data': serialize_encrypted_data(scheme, encrypted_data)
    }

    # Add second dataset for add_encrypted operation
    if operation == 'add_encrypted':
        data_to_compute['serialized_data2'] = data_to_compute['serialized_data']

    # Send data and receive result
    print("> Sending data to server for computation")
    send_data(sock, json.dumps(data_to_compute))

    print("> Waiting for server result...")
    serialized_data = receive_data(sock)

    # Process result
    encrypted_result = deserialize_encrypted_data(scheme, serialized_data, public_key)
    decrypted_result = decrypt_messages(scheme, private_key, encrypted_result)

#ANCHOR - CLIENT
def client(sock, scheme, config, public_key, private_key):
    """Client main function"""
    folder_prefix = config["folder_prefix"] if config["folder_prefix"] != "" else f"client_{config['operation']}_{config['nb_vitals']}bits"
    annotation_str = (
        f"Client Operation | "
        f"NB_RUNS={config['nb_runs']}, "
        f"NB_VITALS={config['nb_vitals']}, "
        f"NB_PATIENTS={config['nb_patients']}, "
        f"KEY_LENGTH={config['key_length']}, "
        f"OPERATION={config['operation']}, "
        f"SCHEME={config['scheme']}"
    )

    benchmarked_fn = profile_and_monitor(
        number=config['nb_runs'],
        folder_prefix=folder_prefix,
        annotation=annotation_str
    )(run_client_operations)

    benchmarked_fn(sock, scheme, config['operation'], public_key, private_key, config)
#!SECTION - END CLIENT WORKFLOW

#SECTION - SERVER WORKFLOW
#ANCHOR - RUN OPERATIONS
def run_server_operations(sock, scheme, config, public_key):
    """Run server operations efficiently"""
    measure_latency_server(sock)

    print("> Waiting for client data...")
    data_to_compute = json.loads(receive_data(sock))
    operation = data_to_compute['operation']
    scalar = data_to_compute['scalar']

    # Process input data
    enc_msgs = deserialize_encrypted_data(scheme, data_to_compute['serialized_data'], public_key)
    enc_msgs2 = deserialize_encrypted_data(scheme, data_to_compute['serialized_data2'], public_key) if operation == 'add_encrypted' else None

    # Perform operations
    result = perform_homomorphic_operation(
        scheme,
        operation, 
        enc_msgs, 
        scalar=scalar, 
        data_list2=enc_msgs2,
        nb_operations=config['nb_operations']
    )

    # Send result
    serialized_result = serialize_encrypted_data(scheme, result)
    print("> Sending computation result back to client")
    send_data(sock, serialized_result)

#ANCHOR - SERVER
def server(sock, scheme, config, public_key):
    """Server main function"""
    folder_prefix = config["folder_prefix"] if config["folder_prefix"] != "" else f"server_{config['operation']}_{config['nb_vitals']}bits"
    annotation_str = (
        f"Server Operation | "
        f"NB_RUNS={config['nb_runs']}, "
        f"NB_VITALS={config['nb_vitals']}, "
        f"NB_PATIENTS={config['nb_patients']}, "
        f"KEY_LENGTH={config['key_length']}, "
        f"OPERATION={config['operation']}, "
        f"SCHEME={config['scheme']}"
    )

    benchmarked_fn = profile_and_monitor(
        number=config['nb_runs'],
        folder_prefix=folder_prefix,
        annotation=annotation_str
    )(run_server_operations)

    benchmarked_fn(sock, scheme, config, public_key)
#!SECTION - END SERVER WORKFLOW

#SECTION - MAIN
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action='store_true', help="Run as server")
    parser.add_argument("--client", type=str, help="Run as client, specify server IP")
    parser.add_argument("--port", type=int, default=12345, help="Port to use for communication (default: 12345)")
    parser.add_argument("--operation", type=str, default="add",
                        help="Operation(s): 'add', 'add_encrypted', 'mul', 'div', 'all' or comma-separated list.")
    parser.add_argument("--nb_runs", type=int, default=2, help="Number of runs for the benchmark")
    parser.add_argument("--nb_vitals", type=str, default="1024",
                        help="Number of vitals per patient (integer or comma-separated list of values to test)")
    parser.add_argument("--nb_patients", type=str, default="4",
                        help="Number of patients (integer or comma-separated list of values to test)")
    parser.add_argument("--key_length", type=str, default="4096",
                        help="Key length in bits (integer or comma-separated list of values to test)")
    parser.add_argument("--nb_operations", type=int, default=16,
                        help="Number of homomorphic operations to perform per run")
    parser.add_argument("--folder_prefix", type=str, default="", help="Folder name for results")
    parser.add_argument("--scheme", type=str, default="paillier",
                        help="Homomorphic encryption scheme to use (default: paillier)")

    args = parser.parse_args()

    # Validate scheme
    if args.scheme not in SCHEMES:
        raise ValueError(f"Unsupported scheme: {args.scheme}. Available schemes: {', '.join(SCHEMES.keys())}")
    scheme = SCHEMES[args.scheme]

    # Parse operations
    operations = (
        ['add', 'add_encrypted', 'mul', 'div'] if args.operation == 'all'
        else [x.strip() for x in args.operation.split(',')] if ',' in args.operation
        else [args.operation]
    )

    # Parse number of vitals and patients
    nb_vitals_list = (
        [int(x.strip()) for x in args.nb_vitals.split(',')] if ',' in args.nb_vitals
        else [int(args.nb_vitals)]
    )
    nb_patients_list = (
        [int(x.strip()) for x in args.nb_patients.split(',')] if ',' in args.nb_patients
        else [int(args.nb_patients)]
    )

    # Parse key lengths
    key_length_list = (
        [int(x.strip()) for x in args.key_length.split(',')] if ',' in args.key_length
        else [int(args.key_length)]
    )

    # Server mode
    if args.server:
        server_sock = create_socket()
        try:
            server_sock.bind(("0.0.0.0", args.port))
            server_sock.listen(1)
            print(f"Server listening on port {args.port}")
            sock, addr = server_sock.accept()
            print(f"Server accepted connection from {addr}")

            for key_length in key_length_list:
                public_key = receive_public_key(sock, scheme)
                input("Press Enter to start the benchmark.")

                # Single loop for all combinations
                for nb_patients, nb_vitals, operation in itertools.product(nb_patients_list, nb_vitals_list, operations):
                    benchmark.current_network_bytes_sent = 0
                    benchmark.current_network_bytes_received = 0
                    config = {
                        'nb_runs': args.nb_runs,
                        'nb_vitals': nb_vitals,
                        'nb_patients': nb_patients,
                        'key_length': key_length,
                        'operation': operation,
                        'nb_operations': args.nb_operations,
                        'folder_prefix': args.folder_prefix,
                        'scheme': args.scheme
                    }

                    print(Fore.YELLOW)
                    print("Configuration:")
                    for k, v in config.items():
                        print(f"  {k}: {v}")
                    print(Fore.RESET)

                    server(sock, scheme, config, public_key)

            sock.close()
        finally:
            server_sock.close()

    # Client mode
    elif args.client:
        client_sock = create_socket()
        try:
            client_sock.connect((args.client, args.port))
            print(f"Client connected to {args.client}:{args.port}")

            for key_length in key_length_list:
                public_key, private_key = generate_keypair(scheme, key_length)
                send_public_key(client_sock, scheme, public_key)
                input("Press Enter to start the benchmark.")

                # Single loop for all combinations
                for nb_patients, nb_vitals, operation in itertools.product(nb_patients_list, nb_vitals_list, operations):
                    
                    benchmark.current_network_bytes_sent = 0
                    benchmark.current_network_bytes_received = 0
                    config = {
                        'nb_runs': args.nb_runs,
                        'nb_vitals': nb_vitals,
                        'nb_patients': nb_patients,
                        'key_length': key_length,
                        'operation': operation,
                        'nb_operations': args.nb_operations,
                        'folder_prefix': args.folder_prefix,
                        'scheme': args.scheme
                    }

                    print(Fore.YELLOW)
                    print("Configuration:")
                    for k, v in config.items():
                        print(f"  {k}: {v}")
                    print(Fore.RESET)

                    client(client_sock, scheme, config, public_key, private_key)

        finally:
            client_sock.close()

    else:
        print("Please specify either --server or --client <server_ip>. See --help.")
#!SECTION - END MAIN
