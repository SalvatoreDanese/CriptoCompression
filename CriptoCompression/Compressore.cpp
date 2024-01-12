// Implementazione della classe (es. Compressore.cpp)

#include "Compressore.h"
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

using namespace CryptoPP;

// Implementazione del costruttore
Compressore::Compressore() {
    // Inizializzazione degli attributi
    // Generazione delle chiavi RSA

    params.GenerateRandomWithKeySize(rng, 2048);
    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);

}

// Implementazione del distruttore
Compressore::~Compressore() {
    // Eventuale rilascio di risorse allocate
}

void Compressore::setChannel(std::queue<std::string> ch) {
    channel = ch;
}

RSA::PublicKey Compressore::getPublicKey() {
    return RSA::PublicKey(params);

}

RSA::PrivateKey Compressore::getPrivateKey() {
    return RSA::PrivateKey(params);

}

byte* Compressore::getSharedKey() {
    return sharedKey;
}

std::string Compressore::encryptMessageRSA(std::string message, RSA::PublicKey destinationPKey) {
    std::string encrypted;
    RSAES_OAEP_SHA_Encryptor encryptor(destinationPKey);

    StringSource(message, true, new PK_EncryptorFilter(rng, encryptor, new StringSink(encrypted)));

    return encrypted;
    
}

std::string Compressore::decryptMessageRSA(std::string message) {
    std::string decrypted;
    RSAES_OAEP_SHA_Decryptor decryptor(getPrivateKey());

    StringSource(message, true, new PK_DecryptorFilter(rng, decryptor, new StringSink(decrypted)));

    return decrypted;

}

std::string Compressore::signMessageRSA(const std::string& message) {
    RSASSA_PKCS1v15_SHA_Signer signer(getPrivateKey());

    // Firmare il messaggio
    std::string signature;
    StringSource(message, true, new SignerFilter(rng, signer, new StringSink(signature)));


    return signature;
}

// Funzione per verificare la firma di un messaggio
bool Compressore::verifySignatureRSA(const std::string& message, const std::string& signature, const RSA::PublicKey& signerPublicKey) {
    RSASSA_PKCS1v15_SHA_Verifier verifier(signerPublicKey);

    // Verificare la firma
    bool result = false;
    StringSource(signature + message, true, new SignatureVerificationFilter(verifier, new ArraySink((byte*)&result, sizeof(result))));


    return result;
}

std::string Compressore::checkIndexesString() {
    std::string indexes = "";
    
    for (int i = 0; i < std::size(sharedInfo); i++) {
        if (!(sharedInfo[i].empty())) {
            indexes = indexes + std::to_string(i) + ",";
        }
    }
    indexes.pop_back();
    return indexes;

}

std::vector<int> Compressore::tokenizeByComma(std::string receivedInfo) {
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

std::vector<int> Compressore::indexesInCommon(std::string receivedIndexes) {

    std::vector<int> indexes = tokenizeByComma(receivedIndexes);

    std::vector<int> common;

    for (int i = 0; i < indexes.size(); i++) {
        if (i < MAX_SHARED_KNOWLEDGE && !(sharedInfo[indexes[i]].empty())) {
            common.push_back(indexes[i]);
        }
        
    }
    
    return common;
}

std::string Compressore::createDisposition(std::vector<int> commonIndexes) {
    CryptoPP::AutoSeededRandomPool rnd;
    std::string indexDisposition = "";

    for (int i = 0; i < 20; i++) {
        int rand = rnd.GenerateWord32(0, commonIndexes.size() - 1);
        indexDisposition = indexDisposition + std::to_string(commonIndexes[rand]) + ",";
    }

    return indexDisposition;
}

byte* Compressore::convertToByte(std::string concatenation) {


    std::size_t size = concatenation.size();
    byte* byteArray = new byte[size]; // Allocazione della memoria

    // Copia i byte della stringa nell'array
    std::memcpy(byteArray, concatenation.data(), size);

    return byteArray;

}

std::string Compressore::calculateHash(std::string& input) {
    SHA256 hash;
    std::string hashStr;

    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(hashStr))));
    return hashStr;

}


void Compressore::createSharedKey(std::string disposition) {
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

unsigned int Compressore::rabin_fingerprint(std::string& text, unsigned int prime) {
    unsigned int result = 0;
    for (char c : text) {
        result = (result * 256 + static_cast<unsigned int>(c)) % prime;
    }
    return result;
}

void Compressore::calculateSharedInfo() {
    
    std::string directory_path = "CompressorFiles";
    

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

std::unordered_map<int, std::string> Compressore::chooseIndexes(int remaining, std::vector<int> &commonIndexes) {
   
    std::vector<int> missingIndexes;
    std::unordered_map<int, std::string> choosenIndexes;

    for (int i = 0; i < std::size(sharedInfo); i++) {
        if (!(sharedInfo[i].empty()) && std::find(commonIndexes.begin(), commonIndexes.end(), i) == commonIndexes.end()) {
            missingIndexes.push_back(i);
        }
    }

    CryptoPP::AutoSeededRandomPool rnd;



    for (int i = 0; i < remaining; i++) {
        int rand = rnd.GenerateWord32(0, missingIndexes.size() - 1);
        choosenIndexes[missingIndexes[rand]] = sharedInfo[missingIndexes[rand]];
        commonIndexes.push_back(missingIndexes[rand]);
        missingIndexes.erase(missingIndexes.begin() + rand);
    }

    return choosenIndexes;

}