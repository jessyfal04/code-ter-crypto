import socket
import random
import argparse
import json
import struct
import time
from colorama import Fore
import itertools
from abc import ABC, abstractmethod
import base64
import os

#NOTE HE LIBRARY
from phe import paillier
import tenseal as ts
from concrete import fhe

#NOTE BENCHMARK LIBRARY
import benchmark
from benchmark import profile_and_monitor

#NOTE CONSTANTS
BUFFER_SIZE = 4096

def reset_benchmark():
    benchmark.current_network_bytes_sent = 0
    benchmark.current_network_bytes_received = 0
    benchmark.current_network_latency = 0
    benchmark.encrypt_start_time = 0
    benchmark.encrypt_end_time = 0
    benchmark.operation_start_time = 0
    benchmark.operation_end_time = 0
    benchmark.decrypt_start_time = 0
    benchmark.decrypt_end_time = 0

#SECTION - HE SCHEMES
class HEScheme(ABC):
    """Abstract base class for homomorphic encryption schemes"""
    
    @abstractmethod
    def generate_contexts(self, key_length, operation=None):
        """Generate public and private contexts for the scheme"""
        pass
    
    @abstractmethod
    def encrypt(self, public_context, message):
        """Encrypt a message"""
        pass
    
    @abstractmethod
    def decrypt(self, private_context, encrypted_message):
        """Decrypt an encrypted message"""
        pass
    
    @abstractmethod
    def serialize_encrypted(self, encrypted_number_list):
        """Serialize encrypted data"""
        pass
    
    @abstractmethod
    def deserialize_encrypted(self, serialized_data, public_context):
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
    def multiply_encrypted(self, enc1, enc2):
        """Multiply two encrypted numbers"""
        pass
    
    @abstractmethod
    def serialize_public_context(self, public_context):
        """Serialize public context"""
        pass
    
    @abstractmethod
    def deserialize_public_context(self, serialized_context):
        """Deserialize public context"""
        pass

class PaillierScheme(HEScheme):
    """Paillier homomorphic encryption scheme implementation"""
    
    def generate_contexts(self, key_length, operation=None):
        """Generate a Paillier keypair with optimized parameters"""
        print(f"> Generating Keypair of length {key_length} bits")
        return paillier.generate_paillier_keypair(n_length=key_length)
    
    def encrypt(self, public_context, message):
        """Encrypt a message using Paillier"""
        return public_context.encrypt(message)
    
    def decrypt(self, private_context, encrypted_message):
        """Decrypt an encrypted message using Paillier"""
        return private_context.decrypt(encrypted_message)
    
    def serialize_encrypted(self, encrypted_number_list):
        """Serialize encrypted data for Paillier"""
        print("> Serializing encrypted data")
        enc_dict = {
            'values': [
                (str(x.ciphertext()), x.exponent) for x in encrypted_number_list
            ]
        }
        return json.dumps(enc_dict)
    
    def deserialize_encrypted(self, serialized_data, public_context):
        """Deserialize encrypted data for Paillier"""
        print("> Deserializing encrypted data")
        data_dict = json.loads(serialized_data)
        return [
            paillier.EncryptedNumber(public_context, int(ctxt), int(exp))
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
    
    def multiply_encrypted(self, enc1, enc2):
        """Multiply two encrypted numbers using Paillier"""
        raise NotImplementedError("Paillier does not support multiplication of encrypted numbers")
    
    def serialize_public_context(self, public_context):
        """Serialize Paillier public key"""
        return {'public_key': {'g': public_context.g, 'n': public_context.n}}
    
    def deserialize_public_context(self, serialized_context):
        """Deserialize Paillier public key"""
        public_context_dict = json.loads(serialized_context)['public_key']
        return paillier.PaillierPublicKey(n=int(public_context_dict['n']))

class BFVScheme(HEScheme):
    """BFV homomorphic encryption scheme implementation using TenSEAL"""
    
    def generate_contexts(self, key_length, operation=None):
        """Generate a BFV keypair with optimized parameters"""
        print(f"> Generating Keypair of length {key_length} bits")
        context = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=key_length, plain_modulus=1032193)
        context.generate_galois_keys()
        private_context = context.secret_key()
        context.make_context_public()
        return context, private_context
    
    def encrypt(self, public_context, message):
        """Encrypt a message using BFV"""
        if isinstance(message, list):
            return ts.bfv_vector(public_context, message)
        else:
            return ts.bfv_vector(public_context, [message])
    
    def decrypt(self, private_context, encrypted_message):
        """Decrypt an encrypted message using BFV"""
        return encrypted_message.decrypt(private_context)
    
    def serialize_encrypted(self, encrypted_number_list):
        """Serialize encrypted data for BFV"""
        print("> Serializing encrypted data")
        # Serialize each encrypted vector and convert to base64
        serialized_list = []
        for enc in encrypted_number_list:
            serialized = enc.serialize()
            serialized_list.append(base64.b64encode(serialized).decode('utf-8'))
        return json.dumps(serialized_list)
    
    def deserialize_encrypted(self, serialized_data, public_context):
        """Deserialize encrypted data for BFV"""
        print("> Deserializing encrypted data")
        # Deserialize each encrypted vector from base64
        serialized_list = json.loads(serialized_data)
        return [ts.bfv_vector_from(public_context, base64.b64decode(serialized)) for serialized in serialized_list]
    
    def add_scalar(self, enc, scalar):
        """Add a scalar to an encrypted number using BFV"""
        scalar_vector = [scalar] * len(enc.decrypt())
        encrypted_scalar = ts.bfv_vector(enc.context(), scalar_vector)
        return enc + encrypted_scalar
    
    def add_encrypted(self, enc1, enc2):
        """Add two encrypted numbers using BFV"""
        return enc1 + enc2
    
    def multiply_scalar(self, enc, scalar):
        """Multiply an encrypted number by a scalar using BFV"""
        scalar_vector = [scalar] * len(enc.decrypt())
        encrypted_scalar = ts.bfv_vector(enc.context(), scalar_vector)
        return enc * encrypted_scalar
    
    def multiply_encrypted(self, enc1, enc2):
        """Multiply two encrypted numbers using BFV"""
        return enc1 * enc2
    
    def serialize_public_context(self, public_context):
        """Serialize BFV public context"""
        serialized = public_context.serialize()
        return base64.b64encode(serialized).decode('utf-8')
    
    def deserialize_public_context(self, serialized_context):
        """Deserialize BFV public context"""
        serialized_bytes = base64.b64decode(serialized_context)
        return ts.context_from(serialized_bytes)

class CKKSScheme(HEScheme):
    """CKKS homomorphic encryption scheme implementation using TenSEAL"""
    
    def generate_contexts(self, key_length, operation=None):
        """Generate a CKKS keypair with optimized parameters"""
        print(f"> Generating Keypair of length {key_length} bits")
        context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=key_length)
        context.global_scale = pow(2, 40)  # Set appropriate scale for CKKS
        context.generate_galois_keys()
        private_context = context.secret_key()
        context.make_context_public()
        return context, private_context
    
    def encrypt(self, public_context, message):
        """Encrypt a message using CKKS"""
        if isinstance(message, list):
            return ts.ckks_vector(public_context, message)
        else:
            return ts.ckks_vector(public_context, [message])
    
    def decrypt(self, private_context, encrypted_message):
        """Decrypt an encrypted message using CKKS"""
        return encrypted_message.decrypt(private_context)
    
    def serialize_encrypted(self, encrypted_number_list):
        """Serialize encrypted data for CKKS"""
        print("> Serializing encrypted data")
        # Serialize each encrypted vector and convert to base64
        serialized_list = []
        for enc in encrypted_number_list:
            serialized = enc.serialize()
            serialized_list.append(base64.b64encode(serialized).decode('utf-8'))
        return json.dumps(serialized_list)
    
    def deserialize_encrypted(self, serialized_data, public_context):
        """Deserialize encrypted data for CKKS"""
        print("> Deserializing encrypted data")
        # Deserialize each encrypted vector from base64
        serialized_list = json.loads(serialized_data)
        return [ts.ckks_vector_from(public_context, base64.b64decode(serialized)) for serialized in serialized_list]
    
    def add_scalar(self, enc, scalar):
        """Add a scalar to an encrypted number using CKKS"""
        scalar_vector = [scalar] * len(enc.decrypt())
        encrypted_scalar = ts.ckks_vector(enc.context(), scalar_vector)
        return enc + encrypted_scalar
    
    def add_encrypted(self, enc1, enc2):
        """Add two encrypted numbers using CKKS"""
        return enc1 + enc2
    
    def multiply_scalar(self, enc, scalar):
        """Multiply an encrypted number by a scalar using CKKS"""
        scalar_vector = [scalar] * len(enc.decrypt())
        encrypted_scalar = ts.ckks_vector(enc.context(), scalar_vector)
        return enc * encrypted_scalar
    
    def multiply_encrypted(self, enc1, enc2):
        """Multiply two encrypted numbers using CKKS"""
        return enc1 * enc2
    
    def serialize_public_context(self, public_context):
        """Serialize CKKS public context"""
        serialized = public_context.serialize()
        return base64.b64encode(serialized).decode('utf-8')
    
    def deserialize_public_context(self, serialized_context):
        """Deserialize CKKS public context"""
        serialized_bytes = base64.b64decode(serialized_context)
        return ts.context_from(serialized_bytes)

class TFHEScheme(HEScheme):
    """TFHE homomorphic encryption scheme implementation using Concrete"""
    
    def generate_contexts(self, key_length, operation=None):
        """Generate TFHE circuit and keys"""
        print(f"> Generating TFHE circuit for operation {operation}")
        
        # Define the function to compile based on operation
        if operation == "add_encrypted":
            def functionToCompile(x, y):
                return x + y
            input_types = {"x": "encrypted", "y": "encrypted"}
        elif operation == 'add_scalar':
            def functionToCompile(x, s):
                return x + s
            input_types = {"x": "encrypted", "s": "clear"}
        elif operation == 'mul_encrypted':
            def functionToCompile(x, y):
                return x * y
            input_types = {"x": "encrypted", "y": "encrypted"}
        elif operation == 'mul_scalar':
            def functionToCompile(x, s):
                return x * s
            input_types = {"x": "encrypted", "s": "clear"}
        else:
            raise ValueError(f"Unsupported operation: {operation}")
        
        # Compile the circuit
        compiler = fhe.Compiler(functionToCompile, input_types)
        inputset = [(i, j) for i in range(10) for j in range(128)]
        circuit = compiler.compile(inputset)
        circuit.keygen()
        
        # Generate contexts
        private_context = {"circuit_client": circuit.client}
        public_context = {
            "circuit_server": circuit.server,
            "evaluation_keys": circuit.client.evaluation_keys
        }
        
        return public_context, private_context
    
    def encrypt(self, public_context, message):
        """Encrypt a message using TFHE"""
        raise NotImplementedError()
    
    def decrypt(self, private_context, encrypted_message):
        """Decrypt an encrypted message using TFHE"""
        return private_context["circuit_client"].decrypt(encrypted_message)
    
    def serialize_encrypted(self, encrypted_data):
        """Serialize encrypted data for TFHE"""
        print("> Serializing encrypted data")
        raise NotImplementedError()
    
    def deserialize_encrypted(self, serialized_data, public_context):
        """Deserialize encrypted data for TFHE"""
        print("> Deserializing encrypted data")
        serialized_list = json.loads(serialized_data)
        return tuple([fhe.Value.deserialize(base64.b64decode(ei)) for ei in serialized_list])
    
    def add_scalar(self, enc, scalar):
        """Add a scalar to an encrypted number using TFHE"""
        raise NotImplementedError("This operation is handled by the circuit")
    
    def add_encrypted(self, enc1, enc2):
        """Add two encrypted numbers using TFHE"""
        # This operation is handled by the circuit
        raise NotImplementedError("This operation is handled by the circuit")
    
    def multiply_scalar(self, enc, scalar):
        """Multiply an encrypted number by a scalar using TFHE"""
        # This operation is handled by the circuit
        raise NotImplementedError("This operation is handled by the circuit")
    
    def multiply_encrypted(self, enc1, enc2):
        """Multiply two encrypted numbers using TFHE"""
        # This operation is handled by the circuit
        raise NotImplementedError("This operation is handled by the circuit")
    
    def serialize_public_context(self, public_context):
        """Serialize TFHE public context"""
        # Save server circuit to file
        public_context["circuit_server"].save("server.zip")
        with open("server.zip", "rb") as f:
            circuit_server_bytes = base64.b64encode(f.read()).decode('utf-8')
        os.remove("server.zip")
        
        # Serialize evaluation keys to base64
        evaluation_keys_bytes = public_context["evaluation_keys"].serialize()
        evaluation_keys_base64 = base64.b64encode(evaluation_keys_bytes).decode('utf-8')
        
        return {
            "circuit_server": circuit_server_bytes,
            "evaluation_keys": evaluation_keys_base64
        }
    
    def deserialize_public_context(self, serialized_context):
        """Deserialize TFHE public context"""
        # Load from json
        serialized_context = json.loads(serialized_context)
        # Load server circuit from base64
        server_circuit_bytes = base64.b64decode(serialized_context["circuit_server"])
        with open("server.zip", "wb") as f:
            f.write(server_circuit_bytes)
        
        circuit_server = fhe.Server.load("server.zip")
        os.remove("server.zip")
        
        # Deserialize evaluation keys from base64
        evaluation_keys_bytes = base64.b64decode(serialized_context["evaluation_keys"])
        evaluation_keys = fhe.EvaluationKeys.deserialize(evaluation_keys_bytes)
        
        return {
            "circuit_server": circuit_server,
            "evaluation_keys": evaluation_keys
        }

# Dictionary of available schemes
SCHEMES = {
    'paillier': PaillierScheme(),
    'bfv': BFVScheme(),
    'ckks': CKKSScheme(),
    'tfhe': TFHEScheme()
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

#SECTION - HOMOMORPHIC OPERATIONS
#ANCHOR - PERFORM OPERATION
def perform_homomorphic_operation(scheme, operation, data_list, scalar=None, data_list2=None, nb_operations=1, public_context=None):
    """Perform a homomorphic operation on encrypted data"""
    print(f"> Performing homomorphic operation {operation}, {nb_operations} times")
    result = data_list

    # Special handling for TFHE scheme
    if isinstance(scheme, TFHEScheme):
        for _ in range(nb_operations):
            if operation == 'add_scalar':
                result = [
                    public_context["circuit_server"].run(
                        enc,
                        evaluation_keys=public_context["evaluation_keys"]
                    )
                    for enc in data_list
                ]
            elif operation == 'add_encrypted':
                result = [
                    public_context["circuit_server"].run(
                        enc,
                        evaluation_keys=public_context["evaluation_keys"]
                    )
                    for enc in data_list
                ]
            elif operation == 'mul_scalar':
                result = [
                    public_context["circuit_server"].run(
                        enc,
                        evaluation_keys=public_context["evaluation_keys"]
                    )
                    for enc in data_list
                ]
            elif operation == 'mul_encrypted':
                result = [
                    public_context["circuit_server"].run(
                        enc,
                        evaluation_keys=public_context["evaluation_keys"]
                    )
                    for enc in data_list
                ]
            else:
                raise ValueError(f"Unsupported operation: {operation}")
    else:
        # Original implementation for other schemes
        for _ in range(nb_operations):
            if operation == 'add_scalar':
                result = [scheme.add_scalar(m, scalar) for m in result]
            elif operation == 'add_encrypted':
                result = [scheme.add_encrypted(m, data_list2[i]) for i, m in enumerate(result)]
            elif operation == 'mul_scalar':
                result = [scheme.multiply_scalar(m, scalar) for m in result]
            elif operation == 'mul_encrypted':
                result = [scheme.multiply_encrypted(m, data_list2[i]) for i, m in enumerate(result)]
            else:
                raise ValueError(f"Unsupported operation: {operation}")
    
    return result
#!SECTION - END HOMOMORPHIC OPERATIONS

#SECTION - KEY EXCHANGE
#ANCHOR - SEND KEY
def send_public_context(sock, scheme, public_context):
    """Send public key efficiently"""
    print("> Sending Public Key to Server")
    key_data = scheme.serialize_public_context(public_context)
    send_data(sock, json.dumps(key_data))
    
    # Wait for server completion
    print("> Waiting for server completion...")
    if receive_data(sock) != "finished":
        raise ValueError("Unexpected response from server")

#ANCHOR - RECEIVE KEY
def receive_public_context(sock, scheme):
    """Receive public key efficiently"""
    print("> Receiving Public Key from Client")
    data = receive_data(sock)
    public_context = scheme.deserialize_public_context(data)
    
    # Signal completion to client
    print("> Signaling completion to client...")
    send_data(sock, "finished")
    return public_context
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
def run_client_operations(sock, scheme, operation, public_context, private_context, config):
    """Run client operations efficiently"""
    measure_latency_client(sock)

    nb_patients = config['nb_patients']
    nb_vitals = config['nb_vitals']

    # Generate and process medical data
    medical_data = generate_mock_medical_data(nb_patients, nb_vitals)
    flattened_data = flatten_medical_data(medical_data)
    scalar = random.getrandbits(1024)

    # Encrypt data
    benchmark.encrypt_start_time = time.perf_counter()
    if isinstance(scheme, TFHEScheme):
        print("> Encrypting and Serializing data")
        # For TFHE, we need to encrypt pairs of data together
        data2 = flattened_data if "encrypted" in operation else [scalar] * len(flattened_data)
        encrypted_data = json.dumps([
            tuple([base64.b64encode(ei.serialize()).decode('utf-8') for ei in private_context["circuit_client"].encrypt(d1, d2)])
            for d1, d2 in zip(flattened_data, data2)
        ])
    else:
        encrypted_data = [scheme.encrypt(public_context, m) for m in flattened_data]
    print(f"> Computing {operation} on {nb_patients} patients (each with {nb_vitals} vitals)")

    # Prepare data for computation
    data_to_compute = {
        'operation': operation,
        'scalar': scalar,
        'data': scheme.serialize_encrypted(encrypted_data) if not isinstance(scheme, TFHEScheme) else encrypted_data
    }
    benchmark.encrypt_end_time = time.perf_counter()

    # Add second dataset for add_encrypted operation
    if "encrypted" in operation and not isinstance(scheme, TFHEScheme):
        data_to_compute['data2'] = data_to_compute['data']

    # Send data and receive result
    print("> Sending data to server for computation")
    send_data(sock, json.dumps(data_to_compute))

    print("> Waiting for server result...")
    serialized_data = receive_data(sock)

    # Process result
    benchmark.decrypt_start_time = time.perf_counter()
    encrypted_result = scheme.deserialize_encrypted(serialized_data, public_context)
    decrypted_result = [scheme.decrypt(private_context, m) for m in encrypted_result]
    benchmark.decrypt_end_time = time.perf_counter()

    # print(f"Data: {flattened_data}")
    # print(f"Result: {decrypted_result}")

    # Signal completion to server
    print("> Signaling completion to server...")
    send_data(sock, "finished")

#ANCHOR - CLIENT
def client(sock, scheme, config, public_context, private_context):
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

    benchmarked_fn(sock, scheme, config['operation'], public_context, private_context, config)
#!SECTION - END CLIENT WORKFLOW

#SECTION - SERVER WORKFLOW
#ANCHOR - RUN OPERATIONS
def run_server_operations(sock, scheme, config, public_context):
    """Run server operations efficiently"""
    measure_latency_server(sock)

    print("> Waiting for client data...")
    data_to_compute = json.loads(receive_data(sock))
    operation = data_to_compute['operation']
    scalar = data_to_compute['scalar']
    
    data_list = None
    data_list2 = None
    # Process input data
    if isinstance(scheme, TFHEScheme):
        data_list = [
            tuple([fhe.Value.deserialize(base64.b64decode(ei)) for ei in encrypted_data])
            for encrypted_data in json.loads(data_to_compute['data'])
        ]
    else:
        data_list = scheme.deserialize_encrypted(data_to_compute['data'], public_context)
        data_list2 = scheme.deserialize_encrypted(data_to_compute['data2'], public_context) if "encrypted" in operation else None

    # Perform operations
    benchmark.operation_start_time = time.perf_counter()
    result = perform_homomorphic_operation(
        scheme,
        operation, 
        data_list, 
        scalar=scalar, 
        data_list2=data_list2,
        nb_operations=config['nb_operations'],
        public_context=public_context
    )
    benchmark.operation_end_time = time.perf_counter()

    # Send result
    if isinstance(scheme, TFHEScheme):
        serialized_result = json.dumps(
            tuple([base64.b64encode(er.serialize()).decode('utf-8') for er in result])
        )
    else:
        serialized_result = scheme.serialize_encrypted(result)
    print("> Sending computation result back to client")
    send_data(sock, serialized_result)

    # Wait for client completion
    print("> Waiting for client completion...")
    if receive_data(sock) != "finished":
        raise ValueError("Unexpected response from client")

#ANCHOR - SERVER
def server(sock, scheme, config, public_context):
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

    benchmarked_fn(sock, scheme, config, public_context)
#!SECTION - END SERVER WORKFLOW

#SECTION - MAIN
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action='store_true', help="Run as server")
    parser.add_argument("--client", type=str, help="Run as client, specify server IP")
    parser.add_argument("--port", type=int, default=12345, help="Port to use for communication (default: 12345)")
    parser.add_argument("--operation", type=str, default="all",
                        help="Operation(s): 'add', 'add_encrypted', 'mul', 'all' or comma-separated list.")
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
                        help="Homomorphic encryption scheme(s) to use (default: paillier). Can be a comma-separated list of schemes: paillier,bfv,ckks")

    args = parser.parse_args()

    # Parse schemes
    schemes_list = (
        [x.strip() for x in args.scheme.split(',')] if ',' in args.scheme
        else [args.scheme]
    )

    # Validate schemes
    for scheme_name in schemes_list:
        if scheme_name not in SCHEMES:
            raise ValueError(f"Unsupported scheme: {scheme_name}. Available schemes: {', '.join(SCHEMES.keys())}")

    # Parse operations
    operations = args.operation.split(',') if ',' in args.operation else \
                ['add_scalar', 'add_encrypted', 'mul_scalar', 'mul_encrypted'] if args.operation == 'all' else [args.operation]

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

            for scheme_name in schemes_list:
                scheme = SCHEMES[scheme_name]
                for key_length in key_length_list:
                    public_context = receive_public_context(sock, scheme)

                    # Single loop for all combinations
                    for nb_patients, nb_vitals, operation in itertools.product(nb_patients_list, nb_vitals_list, operations):
                        
                        reset_benchmark()
                        config = {
                            'nb_runs': args.nb_runs,
                            'nb_vitals': nb_vitals,
                            'nb_patients': nb_patients,
                            'key_length': key_length,
                            'operation': operation,
                            'nb_operations': args.nb_operations,
                            'folder_prefix': args.folder_prefix,
                            'scheme': scheme_name
                        }

                        print(Fore.YELLOW)
                        print("Configuration:")
                        for k, v in config.items():
                            print(f"  {k}: {v}")
                        print(Fore.RESET)

                        server(sock, scheme, config, public_context)

            sock.close()
        finally:
            server_sock.close()

    # Client mode
    elif args.client:
        client_sock = create_socket()
        try:
            client_sock.connect((args.client, args.port))
            print(f"Client connected to {args.client}:{args.port}")

            for scheme_name in schemes_list:
                scheme = SCHEMES[scheme_name]
                for key_length in key_length_list:

                    bool_contextGenerated = False
                    for operation in operations:
                        if not bool_contextGenerated or scheme_name == "tfhe":
                            public_context, private_context = scheme.generate_contexts(key_length, operation=operation)
                            send_public_context(client_sock, scheme, public_context)
                            bool_contextGenerated = True

                        # Single loop for all combinations
                        for nb_patients, nb_vitals in itertools.product(nb_patients_list, nb_vitals_list):
                            
                            reset_benchmark()
                            config = {
                                'nb_runs': args.nb_runs,
                                'nb_vitals': nb_vitals,
                                'nb_patients': nb_patients,
                                'key_length': key_length,
                                'operation': operation,
                                'nb_operations': args.nb_operations,
                                'folder_prefix': args.folder_prefix,
                                'scheme': scheme_name
                            }

                            print(Fore.YELLOW)
                            print("Configuration:")
                            for k, v in config.items():
                                print(f"  {k}: {v}")
                            print(Fore.RESET)

                            client(client_sock, scheme, config, public_context, private_context)

        finally:
            client_sock.close()

    else:
        print("Please specify either --server or --client <server_ip>. See --help.")
#!SECTION - END MAIN
