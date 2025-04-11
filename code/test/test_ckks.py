import tenseal as ts

def client():
    key_modulus = 4096
    # Generate public and secret keys
    context = ts.context(ts.SCHEME_TYPE.CKKS, 4096, coeff_mod_bit_sizes=[30, 20, 20, 30])
    context.global_scale = pow(2, 20)
    context.generate_galois_keys()

    # Generate secret key and drop secret key from public context
    secret_key = context.secret_key()
    context.make_context_public()

    # Encrypt data and scalar
    data = [60, 66, 73, 81, 90]
    scalar = 2
    # Create a vector of the same size as data, filled with the scalar value
    scalar_vector = [scalar] * len(data)

    encrypted_data = ts.ckks_vector(context, data)
    #encrypted_scalar = ts.ckks_vector(context, scalar_vector)

    encrypted_result = server(encrypted_data, scalar)

    print(encrypted_data.scale())

    # Decrypt the result
    decrypted_result = encrypted_result.decrypt(secret_key) 
    print(decrypted_result)

def server(encrypted_data, encrypted_scalar):
    # Add encrypted data and scalar
    encrypted_add = encrypted_data + encrypted_scalar
    return encrypted_add    

if __name__ == "__main__":
    client()