// Implementazione della classe (es. Decompressore.cpp)

#include "Decompressore.h"
#include <array>
#include <vector>
#include <cryptopp/osrng.h>
#include <cstddef>
#include <cstring>
#include <algorithm>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>
#include "cryptopp/hex.h"

// Implementazione del costruttore
Decompressore::Decompressore() {
    // Inizializzazione degli attributi, se necessario
        // Generazione delle chiavi RSA
    params.GenerateRandomWithKeySize(rng, 2048);
    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);
    sharedInfo[0] = "ciao";
    sharedInfo[1] = "ok";
    sharedInfo[2] = "ciao";
    sharedInfo[3] = "ok";
    sharedInfo[4] = "ciao";
    sharedInfo[5] = "ok";
}

// Implementazione del distruttore
Decompressore::~Decompressore() {
    // Eventuale rilascio di risorse allocate
}

void Decompressore::setChannel(std::queue<std::string> ch) {
    channel = ch;

}

RSA::PublicKey Decompressore::getPublicKey() {
    return RSA::PublicKey(params);

}

RSA::PrivateKey Decompressore::getPrivateKey() {
    return RSA::PrivateKey(params);

}

byte* Decompressore::getSharedKey() {
    return sharedKey;
}

std::string Decompressore::encryptMessageRSA(std::string message, RSA::PublicKey destinationPKey) {
    std::string encrypted;
    RSAES_OAEP_SHA_Encryptor encryptor(destinationPKey);

    StringSource(message, true, new PK_EncryptorFilter(rng, encryptor, new StringSink(encrypted)));

    return encrypted;

}

std::string Decompressore::decryptMessageRSA(std::string message) {
    std::string decrypted;
    RSAES_OAEP_SHA_Decryptor decryptor(getPrivateKey());

    StringSource(message, true, new PK_DecryptorFilter(rng, decryptor, new StringSink(decrypted)));

    return decrypted;

}

std::string Decompressore::signMessageRSA(const std::string& message) {
    RSASSA_PKCS1v15_SHA_Signer signer(getPrivateKey());

    // Firmare il messaggio
    std::string signature;
    StringSource(message, true, new SignerFilter(rng, signer, new StringSink(signature)));


    return signature;
}

// Funzione per verificare la firma di un messaggio
bool Decompressore::verifySignatureRSA(const std::string& message, const std::string& signature, const RSA::PublicKey& signerPublicKey) {
    RSASSA_PKCS1v15_SHA_Verifier verifier(signerPublicKey);

    // Verificare la firma
    bool result = false;
    StringSource(signature + message, true, new SignatureVerificationFilter(verifier, new ArraySink((byte*)&result, sizeof(result))));


    return result;
}

std::string Decompressore::checkIndexesString() {
    std::string indexes = "";
    for (int i = 0; i < std::size(sharedInfo); i++) {
        if (!(sharedInfo[i].empty())) {
            indexes = indexes + std::to_string(i) + ",";
        }
    }

    return indexes;

}


std::vector<int> Decompressore::tokenizeByComma(std::string receivedInfo) {
    std::string delimiter = ",";

    size_t pos = 0;
    std::string token;

    std::vector<int> common;

    while ((pos = receivedInfo.find(delimiter)) != std::string::npos) {
        token = receivedInfo.substr(0, pos);
        int tokenPosition = std::stoi(token);
        common.push_back(tokenPosition);
        receivedInfo.erase(0, pos + delimiter.length());
    }
    return common;
}

std::string Decompressore::calculateHash(std::string& input) {
    SHA256 hash;
    std::string hashStr;

    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(hashStr))));
    return hashStr;

}


void Decompressore::createSharedKey(std::string permutation) {
    std::vector<int> indexes = tokenizeByComma(permutation);
    std::string concatenation = "";
    for (int i = 0; i < indexes.size(); i++) {
        concatenation = concatenation + sharedInfo[indexes[i]];
    }

    concatenation = calculateHash(concatenation);
    const byte* ikm = reinterpret_cast<const byte*>(concatenation.data());
    const size_t ikmLength = sizeof(ikm) - 1; // -1 per escludere il terminatore null
    hkdf.DeriveKey(sharedKey, derivedKeyLength, ikm, ikmLength, salt, saltLength, info, infoLength);

}

