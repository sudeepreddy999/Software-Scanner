/*
 * Sample Go code with quantum-vulnerable cryptography
 * This file is used for testing the scanner
 */

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/ecdsa"
	"crypto/dsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// VULNERABLE: RSA key generation
func generateRSAKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// VULNERABLE: RSA encryption
func encryptRSA(publicKey *rsa.PublicKey, message []byte) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		message,
		nil,
	)
	return ciphertext, err
}

// VULNERABLE: ECDSA key generation with P-256
func generateECDSAKey() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// VULNERABLE: ECDSA key generation with P-384
func generateECDSAKeyP384() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// VULNERABLE: ECDSA signing
func signECDSA(privateKey *ecdsa.PrivateKey, message []byte) ([]byte, []byte, error) {
	hash := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, nil, err
	}
	return r.Bytes(), s.Bytes(), nil
}

// VULNERABLE: DSA key generation
func generateDSAKey() (*dsa.PrivateKey, error) {
	var privateKey dsa.PrivateKey
	params := &privateKey.Parameters
	
	err := dsa.GenerateParameters(params, rand.Reader, dsa.L2048N256)
	if err != nil {
		return nil, err
	}
	
	err = dsa.GenerateKey(&privateKey, rand.Reader)
	if err != nil {
		return nil, err
	}
	
	return &privateKey, nil
}

// VULNERABLE: Export RSA key to PEM
func exportRSAPrivateKeyPEM(key *rsa.PrivateKey) []byte {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})
	return keyPEM
}

// Safe function (not vulnerable)
func hashData(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func main() {
	fmt.Println("This code contains quantum-vulnerable cryptography")
	
	// Test RSA
	rsaKey, err := generateRSAKey()
	if err != nil {
		fmt.Println("Error generating RSA key:", err)
	} else {
		fmt.Println("Generated RSA key")
		_ = rsaKey
	}
	
	// Test ECDSA
	ecdsaKey, err := generateECDSAKey()
	if err != nil {
		fmt.Println("Error generating ECDSA key:", err)
	} else {
		fmt.Println("Generated ECDSA key")
		_ = ecdsaKey
	}
}
