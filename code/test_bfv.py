import tenseal as ts

def client():
    # Generate public and secret keys
    key_modulus = 4096
    public_context = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=key_modulus, plain_modulus=1032193)
    public_context.generate_galois_keys()

    # Generate secret key and drop secret key from public context
    secret_key = public_context.secret_key()
    public_context.make_context_public()

    # Encrypt data and scalar
    data = [60, 66, 73, 81, 90]
    scalar = 2.9
    # Create a vector of the same size as data, filled with the scalar value
    scalar_vector = [scalar] * len(data)
    encrypted_data = ts.bfv_vector(public_context, data)
    encrypted_scalar = ts.bfv_vector(public_context, scalar_vector)

    encrypted_result = server(encrypted_data, encrypted_scalar)

    # Decrypt the result
    decrypted_result = encrypted_result.decrypt(secret_key)
    print(decrypted_result)

def server(encrypted_data, encrypted_scalar):
    # Add encrypted data and scalar
    encrypted_add = encrypted_data + encrypted_scalar

    return encrypted_add

if __name__ == "__main__":
    client()
