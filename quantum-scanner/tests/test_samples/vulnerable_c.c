/*
 * Sample C code with quantum-vulnerable cryptography (OpenSSL)
 * This file is used for testing the scanner
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/evp.h>

// VULNERABLE: RSA key generation
RSA* generate_rsa_key(int bits) {
    RSA *rsa = RSA_new();
    BIGNUM *bne = BN_new();
    
    if (BN_set_word(bne, RSA_F4) != 1) {
        return NULL;
    }
    
    if (RSA_generate_key_ex(rsa, bits, bne, NULL) != 1) {
        RSA_free(rsa);
        BN_free(bne);
        return NULL;
    }
    
    BN_free(bne);
    return rsa;
}

// VULNERABLE: RSA encryption
int encrypt_rsa(unsigned char *plaintext, int plaintext_len,
                unsigned char *encrypted, RSA *rsa) {
    int result = RSA_public_encrypt(plaintext_len, plaintext,
                                   encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    return result;
}

// VULNERABLE: ECDSA key generation
EC_KEY* generate_ecdsa_key() {
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!EC_KEY_generate_key(eckey)) {
        EC_KEY_free(eckey);
        return NULL;
    }
    return eckey;
}

// VULNERABLE: ECDSA signing
int sign_ecdsa(const unsigned char *message, size_t message_len,
               unsigned char *signature, unsigned int *sig_len,
               EC_KEY *eckey) {
    return ECDSA_sign(0, message, message_len, signature, sig_len, eckey);
}

// VULNERABLE: DSA key generation
DSA* generate_dsa_key() {
    DSA *dsa = DSA_new();
    if (DSA_generate_parameters_ex(dsa, 2048, NULL, 0, NULL, NULL, NULL) != 1) {
        DSA_free(dsa);
        return NULL;
    }
    
    if (DSA_generate_key(dsa) != 1) {
        DSA_free(dsa);
        return NULL;
    }
    
    return dsa;
}

// VULNERABLE: Diffie-Hellman key exchange
DH* generate_dh_params() {
    DH *dh = DH_new();
    if (DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL) != 1) {
        DH_free(dh);
        return NULL;
    }
    
    if (DH_generate_key(dh) != 1) {
        DH_free(dh);
        return NULL;
    }
    
    return dh;
}

// Safe function (not vulnerable)
void hash_data(const char *data, unsigned char *output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, data, strlen(data));
    EVP_DigestFinal_ex(mdctx, output, NULL);
    EVP_MD_CTX_free(mdctx);
}

int main() {
    printf("This code contains quantum-vulnerable cryptography\\n");
    
    // Test RSA
    RSA *rsa = generate_rsa_key(2048);
    if (rsa) {
        printf("Generated RSA key\\n");
        RSA_free(rsa);
    }
    
    return 0;
}
