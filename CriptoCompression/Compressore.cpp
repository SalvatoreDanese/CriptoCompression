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

using namespace CryptoPP;

// Implementazione del costruttore
Compressore::Compressore() {
    // Inizializzazione degli attributi, se necessario
        // Generazione delle chiavi RSA
    AutoSeededRandomPool rng;
    params.GenerateRandomWithKeySize(rng, 2048);
    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);
    shared_info[0] = "ciao";
    shared_info[3] = "ok";

}

// Implementazione del distruttore
Compressore::~Compressore() {
    // Eventuale rilascio di risorse allocate
}

// Implementazione del metodo setMyInt
void Compressore::send(std:: string value) {
    
}

// Implementazione del metodo getMyInt
std:: string Compressore::receive(std::string value) {
    return NULL;
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

std::string Compressore::checkIndexesString() {
    std::string indexes = "";
    
    for (int i = 0; i < std::size(shared_info); i++) {
        if (!(shared_info[i].empty())) {
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
        if (i < shared_info->size() && !(shared_info[indexes[i]].empty())) {
            common.push_back(indexes[i]);
        }
        
    }

    return common;
}

std::string Compressore::permutation(std::vector<int> commonIndexes) {
    CryptoPP::AutoSeededRandomPool rnd;
    std::string indexPermutation = "";

    for (int i = 0; i < 20; i++) {
        int rand = rnd.GenerateWord32(0, commonIndexes.size() - 1);
        indexPermutation = indexPermutation + std::to_string(commonIndexes[rand]) + ",";
    }

    return indexPermutation;
}

byte* Compressore::convertToByte(std::string concatenation) {


    std::size_t size = concatenation.size();
    byte* byteArray = new byte[size]; // Allocazione della memoria

    // Copia i byte della stringa nell'array
    std::memcpy(byteArray, concatenation.data(), size);

    return byteArray;

}


void DeriveKeyWithHKDF(const byte* salt, size_t saltLength,
    const byte* ikm, size_t ikmLength,
    const byte* info, size_t infoLength,
    byte* derivedKey, size_t derivedKeyLength) {
    HKDF<SHA256> hkdf;
    hkdf.DeriveKey(derivedKey, derivedKeyLength, ikm, ikmLength, salt, saltLength, info, infoLength);
}

void Compressore::createSharedKey(std::string permutation) {
    std::vector<int> indexes = tokenizeByComma(permutation);
    std::string concatenation = "";
    for (int i = 0; i < indexes.size(); i++) {
        concatenation = concatenation + shared_info[indexes[i]];
    }


    //const byte* ikm = convertToByte(concatenation);

    
    const byte* ikm = reinterpret_cast<const byte*>(concatenation.data());
    byte salt[] = { 0x00, 0x01, 0x02, 0x03 }; // Salt (puoi generare casualmente) HASH DELLE COSE CHE DOBBIAMO FA
    byte info[] = "Additional Info"; // Additional Info

    const size_t saltLength = sizeof(salt);
    const size_t ikmLength = sizeof(ikm) - 1; // -1 per escludere il terminatore null
    const size_t infoLength = sizeof(info) - 1; // -1 per escludere il terminatore null
    const size_t derivedKeyLength = 32; // Lunghezza della chiave derivata (in byte)
   

    DeriveKeyWithHKDF(salt, saltLength, ikm, ikmLength, info, infoLength, sharedKey, derivedKeyLength);

}

byte* Compressore::getSharedKey() {
    return sharedKey;
}



