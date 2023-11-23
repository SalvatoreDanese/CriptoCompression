// Implementazione della classe (es. Compressore.cpp)

#include "Compressore.h"

// Implementazione del costruttore
Compressore::Compressore() {
    // Inizializzazione degli attributi, se necessario
        // Generazione delle chiavi RSA
    AutoSeededRandomPool rng;
    params.GenerateRandomWithKeySize(rng, 2048);
    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);

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
