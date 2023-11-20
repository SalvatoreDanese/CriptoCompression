#include <iostream>
#include <string>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

// Funzione di callback per notificare l'uso della chiave
void NotifyKeyUsage2(const std::string& keyType, const std::string& action) {
    std::cout << "Key " << keyType << " used for " << action << std::endl;
}


// Funzione per firmare un messaggio
std::string SignMessage(const std::string& message, const RSA::PrivateKey& privateKey) {
    AutoSeededRandomPool rng;
    RSASSA_PKCS1v15_SHA_Signer signer(privateKey);

    // Firmare il messaggio
    std::string signature;
    StringSource(message, true, new SignerFilter(rng, signer, new StringSink(signature)));

    // Notifica l'uso della chiave privata per la firma
    NotifyKeyUsage2("Private", "signing");

    return signature;
}

// Funzione per verificare la firma di un messaggio
bool VerifySignature(const std::string& message, const std::string& signature, const RSA::PublicKey& publicKey) {
    RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);

    // Verificare la firma
    bool result = false;
    StringSource(signature + message, true, new SignatureVerificationFilter(verifier, new ArraySink((byte*)&result, sizeof(result))));

    // Notifica l'uso della chiave pubblica per la verifica
    NotifyKeyUsage2("Public", "verification");

    return result;
}

int funzione1() {
    // Generazione delle chiavi RSA
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 2048);

    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(privateKey);

    // Notifica l'uso delle chiavi
    NotifyKeyUsage2("Private", "generation");
    NotifyKeyUsage2("Public", "generation");

    // Messaggio da firmare
    std::string originalMessage = "Hello, Digital Signature!";

    // Firma del messaggio
    std::string signature = SignMessage(originalMessage, privateKey);

    // Verifica della firma
    bool isValid = VerifySignature(originalMessage, signature, publicKey);

    // Stampa dei risultati
    std::cout << "Original Message: " << originalMessage << std::endl;
    std::cout << "Signature: " << signature << std::endl;
    std::cout << "Signature is " << (isValid ? "valid" : "invalid") << std::endl;

    return 0;
}