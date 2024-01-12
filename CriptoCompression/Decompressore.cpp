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
#include <fstream>
#include <sstream>
#include <experimental/filesystem>

#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING

// Implementazione del costruttore
Decompressore::Decompressore() {
    // Inizializzazione degli attributi, se necessario
        // Generazione delle chiavi RSA
    params.GenerateRandomWithKeySize(rng, 2048);
    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);
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


void Decompressore::createSharedKey(std::string disposition) {


    std::vector<int> indexes = tokenizeByComma(disposition);
    std::string concatenation = "";
    for (int i = 0; i < indexes.size(); i++) {
        concatenation = concatenation + sharedInfo[indexes[i]];
    }

    concatenation = calculateHash(concatenation);
    const byte* ikm = reinterpret_cast<const byte*>(concatenation.data());
    const size_t ikmLength = sizeof(ikm) - 1; // -1 per escludere il terminatore null
    hkdf.DeriveKey(sharedKey, derivedKeyLength, ikm, ikmLength, salt, saltLength, info, infoLength);

}

unsigned int Decompressore::rabin_fingerprint(std::string& text, unsigned int prime) {
    unsigned int result = 0;
    for (char c : text) {
        result = (result * 256 + static_cast<unsigned int>(c)) % prime;
    }
    return result;
}

void Decompressore::calculateSharedInfo() {


    std::string directory_path = "DecompressorFiles";


    try {
        for (const auto& entry : std::experimental::filesystem::directory_iterator(directory_path)) {
            if (std::experimental::filesystem::is_regular_file(entry.path())) {
                std::ifstream inputFile(entry.path());
                std::string inputString, encodedString;
                std::stringstream buf;
                buf << inputFile.rdbuf();
                inputString = buf.str();

                int key = rabin_fingerprint(inputString);
                std::string value = calculateHash(inputString);
                sharedInfo[key] = value;
                inputFile.close();
            }
        }
    }
    catch (const std::experimental::filesystem::filesystem_error& ex) {
        std::cerr << "Errore durante la lettura della directory: " << ex.what() << std::endl;
    }

    std::ifstream inputFile();
}

void Decompressore::addSharedInfo(int key, std::string value) {
    sharedInfo[key] = value;
}

void Decompressore::processMessage(std::string message) {
    if(message.substr(0,4) == "SYNC") {
        std::string delimiter = ":";

        size_t pos = 0;
        std::string token;

        std::vector<int> common;

        std::string synch = message.substr(7, message.size() - 7);
        pos = synch.find(delimiter);
        token = synch.substr(0, pos);
        int key = std::stoi(token);
        std::string value = synch.substr(pos + 1, synch.size() - pos);

        addSharedInfo(key, value);

    }

    else {
        createSharedKey(message);
    }
}