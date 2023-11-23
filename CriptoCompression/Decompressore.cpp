// Implementazione della classe (es. Compressore.cpp)

#include "Decompressore.h"

// Implementazione del costruttore
Decompressore::Decompressore() {
    // Inizializzazione degli attributi, se necessario
        // Generazione delle chiavi RSA
    AutoSeededRandomPool rng;
    params.GenerateRandomWithKeySize(rng, 2048);
    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);
}

// Implementazione del distruttore
Decompressore::~Decompressore() {
    // Eventuale rilascio di risorse allocate
}

// Implementazione del metodo setMyInt
void Decompressore::send(std::string value) {

}

// Implementazione del metodo getMyInt
std::string Decompressore::receive() {
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
