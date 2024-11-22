from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa



def generatic_keys():
# Generate an RSA private key
    private_key = rsa.generate_private_key(
       public_exponent=65537,
       key_size=2048,
       backend=default_backend()
    )

    # Get the public key from the private key
    public_key = private_key.public_key()

    # The keys to PEM format
    private_key_pem = private_key.private_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PrivateFormat.PKCS8,
       encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save the keys to files or use them as needed
    with open('private_key.pem', 'wb') as f:
       f.write(private_key_pem)

    with open('public_key.pem', 'wb') as f:
        f.write(public_key_pem)

