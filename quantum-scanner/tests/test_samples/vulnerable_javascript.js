/**
 * Sample JavaScript code with quantum-vulnerable cryptography
 * This file is used for testing the scanner
 */

const crypto = require('crypto');

// VULNERABLE: RSA key generation
function generateRSAKeys() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
    return { publicKey, privateKey };
}

// VULNERABLE: RSA encryption
function encryptRSA(data, publicKey) {
    return crypto.publicEncrypt(publicKey, Buffer.from(data));
}

// VULNERABLE: RSA decryption
function decryptRSA(encryptedData, privateKey) {
    return crypto.privateDecrypt(privateKey, encryptedData);
}

// VULNERABLE: ECDSA key generation
function generateECDSAKeys() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp256k1',
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'sec1',
            format: 'pem'
        }
    });
    return { publicKey, privateKey };
}

// VULNERABLE: ECDSA signing
function signECDSA(data, privateKey) {
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();
    return sign.sign(privateKey);
}

// VULNERABLE: ECDH key exchange
function performECDH() {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.generateKeys();
    return {
        publicKey: ecdh.getPublicKey(),
        privateKey: ecdh.getPrivateKey()
    };
}

// VULNERABLE: Diffie-Hellman key exchange
function performDH() {
    const dh = crypto.createDiffieHellman(2048);
    dh.generateKeys();
    return {
        publicKey: dh.getPublicKey(),
        privateKey: dh.getPrivateKey()
    };
}

// VULNERABLE: Using node-rsa package
const NodeRSA = require('node-rsa');

function generateRSAWithNodeRSA() {
    const key = new NodeRSA({b: 2048});
    return key;
}

// Safe function (not vulnerable)
function hashData(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

module.exports = {
    generateRSAKeys,
    encryptRSA,
    decryptRSA,
    generateECDSAKeys,
    signECDSA,
    performECDH,
    performDH,
    hashData
};
