"""
Test file demonstrating quantum-vulnerable and quantum-safe (PQC) cryptography
This file should be scanned to verify that the scanner recognizes both:
1. ❌ Vulnerable algorithms (RSA, ECDSA) - should be flagged as CRITICAL
2. ✅ Quantum-safe algorithms (Kyber, Dilithium) - should be flagged as SAFE
"""

# =============================================================================
# VULNERABLE CODE - Should be detected as CRITICAL
# =============================================================================

# RSA encryption - VULNERABLE to quantum attacks
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def generate_rsa_keys():
    """Generate RSA keys - QUANTUM VULNERABLE"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt_data(public_key, plaintext):
    """RSA encryption - QUANTUM VULNERABLE"""
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# ECDSA signatures - VULNERABLE to quantum attacks
from cryptography.hazmat.primitives.asymmetric import ec

def generate_ecdsa_keys():
    """Generate ECDSA keys - QUANTUM VULNERABLE"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def ecdsa_sign_data(private_key, data):
    """ECDSA signature - QUANTUM VULNERABLE"""
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

# DSA - VULNERABLE to quantum attacks
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

def generate_dsa_keys():
    """Generate DSA keys - QUANTUM VULNERABLE"""
    key = DSA.generate(2048)
    return key

# =============================================================================
# QUANTUM-SAFE CODE - Should be detected as SAFE ✅
# =============================================================================

# CRYSTALS-Kyber - Post-Quantum Key Encapsulation Mechanism (KEM)
try:
    from pqcrypto.kem.kyber512 import generate_keypair as kyber_generate
    from pqcrypto.kem.kyber512 import encrypt as kyber_encrypt
    from pqcrypto.kem.kyber512 import decrypt as kyber_decrypt
    
    def generate_kyber_keys():
        """Generate Kyber keys - QUANTUM SAFE ✅"""
        public_key, secret_key = kyber_generate()
        return public_key, secret_key
    
    def kyber_encapsulate(public_key):
        """Kyber key encapsulation - QUANTUM SAFE ✅"""
        ciphertext, shared_secret = kyber_encrypt(public_key)
        return ciphertext, shared_secret
    
    def kyber_decapsulate(secret_key, ciphertext):
        """Kyber key decapsulation - QUANTUM SAFE ✅"""
        shared_secret = kyber_decrypt(secret_key, ciphertext)
        return shared_secret
    
except ImportError:
    print("pqcrypto.kem.kyber not installed - using placeholder")
    # Even without the library, the scanner should detect the patterns
    def placeholder_kyber():
        """This demonstrates Kyber pattern even without library"""
        # kyber512 key generation
        # kyber768 encryption
        # KYBER-1024 usage
        pass

# CRYSTALS-Dilithium - Post-Quantum Digital Signature Algorithm
try:
    from pqcrypto.sign.dilithium2 import generate_keypair as dilithium_generate
    from pqcrypto.sign.dilithium2 import sign as dilithium_sign
    from pqcrypto.sign.dilithium2 import verify as dilithium_verify
    
    def generate_dilithium_keys():
        """Generate Dilithium keys - QUANTUM SAFE ✅"""
        public_key, secret_key = dilithium_generate()
        return public_key, secret_key
    
    def dilithium_sign_message(secret_key, message):
        """Dilithium signature - QUANTUM SAFE ✅"""
        signature = dilithium_sign(secret_key, message)
        return signature
    
    def dilithium_verify_signature(public_key, message, signature):
        """Dilithium verification - QUANTUM SAFE ✅"""
        try:
            dilithium_verify(public_key, message, signature)
            return True
        except:
            return False
            
except ImportError:
    print("pqcrypto.sign.dilithium not installed - using placeholder")
    def placeholder_dilithium():
        """This demonstrates Dilithium pattern even without library"""
        # dilithium2 signing
        # dilithium3 verification
        # DILITHIUM-5 usage
        pass

# SPHINCS+ - Stateless Hash-Based Post-Quantum Signature Scheme
try:
    from pqcrypto.sign.sphincssha256128srobust import generate_keypair as sphincs_generate
    from pqcrypto.sign.sphincssha256128srobust import sign as sphincs_sign
    from pqcrypto.sign.sphincssha256128srobust import verify as sphincs_verify
    
    def generate_sphincs_keys():
        """Generate SPHINCS+ keys - QUANTUM SAFE ✅"""
        public_key, secret_key = sphincs_generate()
        return public_key, secret_key
    
    def sphincs_sign_data(secret_key, data):
        """SPHINCS+ signature - QUANTUM SAFE ✅"""
        signature = sphincs_sign(secret_key, data)
        return signature
        
except ImportError:
    print("pqcrypto.sign.sphincs not installed - using placeholder")
    def placeholder_sphincs():
        """This demonstrates SPHINCS+ pattern even without library"""
        # sphincssha256128f signing
        # SPHINCS+ verification
        pass

# FALCON - Fast-Fourier Lattice-based Compact Signatures
def falcon_example():
    """FALCON signature scheme - QUANTUM SAFE ✅"""
    # from pqcrypto.sign.falcon512 import generate_keypair
    # falcon signature implementation
    # FALCON-1024 for higher security
    pass

# NTRU - Lattice-based encryption
def ntru_example():
    """NTRU encryption - QUANTUM SAFE ✅"""
    # from pqcrypto.kem.ntru import generate_keypair
    # NTRU key encapsulation
    # ntruencrypt usage
    pass

# Classic McEliece - Code-based cryptography
def mceliece_example():
    """Classic McEliece - QUANTUM SAFE ✅"""
    # from pqcrypto.kem.mceliece import generate_keypair
    # McEliece encryption
    # MCELIECE key exchange
    pass

# FrodoKEM - Conservative lattice-based KEM
def frodokem_example():
    """FrodoKEM - QUANTUM SAFE ✅"""
    # from pqcrypto.kem.frodo import generate_keypair
    # FrodoKEM key encapsulation
    # FRODO-976 usage
    pass

# =============================================================================
# DEMONSTRATION FUNCTIONS
# =============================================================================

def demonstrate_vulnerable_crypto():
    """Demonstrate quantum-vulnerable cryptography"""
    print("=== QUANTUM-VULNERABLE CRYPTOGRAPHY ===")
    
    # RSA
    print("\n1. RSA Encryption (VULNERABLE ❌)")
    rsa_private, rsa_public = generate_rsa_keys()
    message = b"Secret message"
    encrypted = rsa_encrypt_data(rsa_public, message)
    print(f"   Encrypted with RSA-2048: {len(encrypted)} bytes")
    
    # ECDSA
    print("\n2. ECDSA Signature (VULNERABLE ❌)")
    ecdsa_private, ecdsa_public = generate_ecdsa_keys()
    signature = ecdsa_sign_data(ecdsa_private, message)
    print(f"   ECDSA signature: {len(signature)} bytes")
    
    # DSA
    print("\n3. DSA Keys (VULNERABLE ❌)")
    dsa_key = generate_dsa_keys()
    print(f"   DSA key generated: {dsa_key.key_size} bits")

def demonstrate_quantum_safe_crypto():
    """Demonstrate post-quantum cryptography"""
    print("\n=== QUANTUM-SAFE CRYPTOGRAPHY ===")
    
    print("\n1. CRYSTALS-Kyber (SAFE ✅)")
    print("   Post-quantum key encapsulation mechanism")
    print("   Based on Module Learning With Errors (MLWE)")
    
    print("\n2. CRYSTALS-Dilithium (SAFE ✅)")
    print("   Post-quantum digital signature algorithm")
    print("   Based on Module Learning With Errors (MLWE)")
    
    print("\n3. SPHINCS+ (SAFE ✅)")
    print("   Stateless hash-based signature scheme")
    print("   Conservative post-quantum security")
    
    print("\n4. FALCON (SAFE ✅)")
    print("   Compact lattice-based signatures")
    print("   Fast verification")
    
    print("\n5. NTRU (SAFE ✅)")
    print("   Lattice-based encryption")
    print("   Efficient operations")
    
    print("\n6. Classic McEliece (SAFE ✅)")
    print("   Code-based cryptography")
    print("   Strong security guarantees")
    
    print("\n7. FrodoKEM (SAFE ✅)")
    print("   Conservative lattice-based KEM")
    print("   Based on plain Learning With Errors")

if __name__ == "__main__":
    print("=" * 70)
    print("QUANTUM CRYPTOGRAPHY TEST FILE")
    print("=" * 70)
    
    demonstrate_vulnerable_crypto()
    demonstrate_quantum_safe_crypto()
    
    print("\n" + "=" * 70)
    print("SCANNER SHOULD DETECT:")
    print("  ❌ RSA, ECDSA, DSA as CRITICAL (quantum-vulnerable)")
    print("  ✅ Kyber, Dilithium, SPHINCS+, FALCON, NTRU, McEliece, FrodoKEM as SAFE")
    print("=" * 70)
