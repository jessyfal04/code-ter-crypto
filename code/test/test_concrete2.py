import base64
from concrete import fhe
import os

OPERATION = "add_encrypted" # Both client and server have the same operation, they know it

def server(publicContextSerialized, encrypted_inputs_serialized):
    # Load the server circuit and evaluation keys
    server_circuit_bytes = base64.b64decode(publicContextSerialized["circuit_server"])
    with open("server.zip", "wb") as f:
        f.write(server_circuit_bytes)
    
    circuit_server = fhe.Server.load("server.zip")
    os.remove("server.zip")
    
    evaluation_keys = fhe.EvaluationKeys.deserialize(publicContextSerialized["evaluation_keys"])

    # Process all encrypted inputs using list comprehension
    return [
        circuit_server.run(
            tuple([fhe.Value.deserialize(ei) for ei in encrypted_input_serialized]),
            evaluation_keys=evaluation_keys
        )
        for encrypted_input_serialized in encrypted_inputs_serialized
    ]

def client(operation = None):
    # === Define the function to compile ===
    if operation == "add_encrypted":
        def functionToCompile(x, y):
            return x + y
    elif operation == 'add_scalar':
        def functionToCompile(x, s):
            return x + s
    elif operation == 'mul_encrypted':
        def functionToCompile(x, y):
            return x * y
    elif operation == 'mul_scalar':
        def functionToCompile(x, s):
            return x * s
    else:
        raise ValueError("Invalid operation")

    # === Compile the functions ===
    if "encrypted" in operation:
        compiler = fhe.Compiler(functionToCompile, {"x": "encrypted", "y": "encrypted"})
    else:
        compiler = fhe.Compiler(functionToCompile, {"x": "encrypted", "s": "clear"})
        
    inputset = [(i, j) for i in range(10) for j in range(10)]
    circuit = compiler.compile(inputset)
    circuit.keygen()

    # === Generate private and public circuits ===
    privateContext = {"circuit_client" : circuit.client}
    publicContext = {"circuit_server" : circuit.server, "evaluation_keys" : circuit.client.evaluation_keys}

    # Read and decode the server circuit from base64
    publicContext["circuit_server"].save("server.zip")
    with open("server.zip", "rb") as f:
        publicContextSerialized = {
            "circuit_server" : base64.b64encode(f.read()).decode('utf-8'),
            "evaluation_keys" : publicContext["evaluation_keys"].serialize()
        }
    os.remove("server.zip")

    # === Encrypt the input ===
    data1 = [1, 2, 3, 4]
    data2 = [5, 6, 7, 8] if "encrypted" in operation else [2] * len(data1)
    
    # Encrypt all pairs of data using list comprehension
    encrypted_inputs_serialized = [
        tuple([ei.serialize() for ei in privateContext["circuit_client"].encrypt(d1, d2)])
        for d1, d2 in zip(data1, data2)
    ]
        
    # === Send all encrypted inputs to the server at once and decrypt results ===
    encrypted_results = server(publicContextSerialized, encrypted_inputs_serialized)
    results = [privateContext["circuit_client"].decrypt(encrypted_result) for encrypted_result in encrypted_results]
    
    # Print results
    for result in results:
        print(f"Result: {result}")
    print(f"All results: {results}")

if __name__ == "__main__":
    client(operation = OPERATION)
