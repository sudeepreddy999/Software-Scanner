"""
Sample Python code with quantum-vulnerable cryptography
This file is used for testing the scanner
"""

# VULNERABLE: Using PyCrypto/PyCryptodome RSA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# VULNERABLE: RSA key generation
def generate_rsa_keys():
    """Generate RSA key pair - VULNERABLE"""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# VULNERABLE: Using cryptography library
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

def generate_cryptography_rsa():
    """Generate RSA using cryptography library - VULNERABLE"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    key1 = 4096
    private_key2 = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key1,  # Variable key size
        backend=default_backend()
    )
    return private_key

# VULNERABLE: ECDSA usage
def generate_ecdsa_keys():
    """Generate ECDSA keys - VULNERABLE"""
    private_key = ec.generate_private_key(
        ec.SECP256R1(),  # Also known as P-256
        default_backend()
    )
    return private_key

# VULNERABLE: DSA usage
from Crypto.PublicKey import DSA

def generate_dsa_keys():
    """Generate DSA keys - VULNERABLE"""
    key = DSA.generate(2048)
    return key

# VULNERABLE: ECDSA signing
def sign_message_ecdsa(private_key, message):
    """Sign message with ECDSA - VULNERABLE"""
    from cryptography.hazmat.primitives.asymmetric import utils
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

# Safe function (not vulnerable)
def hash_password():
    """This is safe - just hashing"""
    import hashlib
    return hashlib.sha256(b"password").hexdigest()
