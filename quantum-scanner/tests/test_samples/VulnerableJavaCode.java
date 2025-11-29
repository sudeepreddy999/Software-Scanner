/**
 * Sample Java code with quantum-vulnerable cryptography
 * This file is used for testing the scanner
 */

import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import java.security.spec.ECGenParameterSpec;

public class VulnerableJavaCode {
    
    // VULNERABLE: RSA key generation
    public static KeyPair generateRSAKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
    
    // VULNERABLE: RSA encryption
    public static byte[] encryptRSA(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }
    
    // VULNERABLE: ECDSA key generation
    public static KeyPair generateECDSAKeys() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec);
        return keyGen.generateKeyPair();
    }
    
    // VULNERABLE: ECDSA signing
    public static byte[] signECDSA(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }
    
    // VULNERABLE: DSA key generation
    public static KeyPair generateDSAKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
    
    // VULNERABLE: Diffie-Hellman key exchange
    public static byte[] performDHKeyExchange(PrivateKey privateKey, PublicKey publicKey) 
            throws Exception {
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(privateKey);
        keyAgree.doPhase(publicKey, true);
        return keyAgree.generateSecret();
    }
    
    // Safe function (not vulnerable)
    public static String hashData(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data.getBytes("UTF-8"));
        return bytesToHex(hash);
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
