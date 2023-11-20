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
void NotifyKeyUsage1(const std::string& keyType, const std::string& action) {
    std::cout << "Key " << keyType << " used for " << action << std::endl;
}

int funzione3() {
    // Generazione delle chiavi RSA
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 2048);

    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);

    // Notifica l'uso delle chiavi
    NotifyKeyUsage1("Private", "generation");
    NotifyKeyUsage1("Public", "generation");

    // Esempio di cifratura e decifrazione di un messaggio
    std::string originalMessage = "Hello, RSA!";
    std::string encrypted, decrypted;

    // Cifratura
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    StringSource(originalMessage, true, new PK_EncryptorFilter(rng, encryptor, new StringSink(encrypted)));

    // Notifica l'uso della chiave pubblica per la cifratura
    NotifyKeyUsage1("Public", "encryption");

    // Decifrazione
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    StringSource(encrypted, true, new PK_DecryptorFilter(rng, decryptor, new StringSink(decrypted)));

    // Notifica l'uso della chiave privata per la decifrazione
    NotifyKeyUsage1("Private", "decryption");

    // Stampa dei risultati
    std::cout << "Original Message: " << originalMessage << std::endl;
    std::cout << "Encrypted Message: " << encrypted << std::endl;
    std::cout << "Decrypted Message: " << decrypted << std::endl;

    return 0;
}