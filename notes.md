tenseal 
- Garder trace de Coefficient modulus sizes	Saved keys	Context serialized size
- Saved keys : ??? all / Secret key / Galois keys / Relin keys

- Context serialized size, new metrics ??

- Polynomial modulus : 4096 / 8192
- Scheme Type : ckks / bfv
- Encryption Type : Always asymmetric

Concrete
- These parameters allow you to generate the right key set, including both secret keys and evaluation keys. Secret keys have the capability of decrypting ciphertexts, and thus should only be accessible to parties doing decryption. Evaluation keys are public material that can be sent to a server in order to run an encrypted computation.