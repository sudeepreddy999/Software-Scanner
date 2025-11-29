# rsa_example.py
# Requires: pip install cryptography
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key

def serialize_private(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def serialize_public(key):
    pub = key.public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def encrypt(pubkey, message: bytes):
    return pubkey.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt(privkey, ciphertext: bytes):
    return privkey.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def sign(privkey, message: bytes):
    return privkey.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verify(pubkey, signature: bytes, message: bytes):
    pubkey.verify(
        signature,
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

if __name__ == "__main__":
    msg = b"Test message for RSA (cryptography)"
    priv = generate_rsa_keypair()
    pub = priv.public_key()

    print("Private key PEM:\n", serialize_private(priv).decode()[:200], "...")
    print("Public key PEM:\n", serialize_public(priv)[:200], "...")

    ct = encrypt(pub, msg)
    print("Ciphertext (first 60 bytes):", ct[:60])

    pt = decrypt(priv, ct)
    print("Decrypted:", pt)

    sig = sign(priv, msg)
    print("Signature (len):", len(sig))

    # verify (raises exception on failure)
    try:
        verify(pub, sig, msg)
        print("Signature verified OK")
    except Exception as e:
        print("Signature verification failed:", e)
        
    key1 = 2048
    rsa.generate_private_key(public_exponent=65537, key_size=key1)
