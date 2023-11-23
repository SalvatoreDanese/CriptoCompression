// Dichiarazione della classe nel file header (es. Decompressore.h)

#ifndef DECCOMPRESSORE_H  // Direttiva per l'inclusione condizionale per evitare inclusioni multiple
#define DECOMPRESSORE_H
#include <string>
#include <iostream>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <queue>

using namespace CryptoPP;

class Decompressore {
public:
    // Membri della classe (attributi e metodi)

    // Costruttore (di solito usato per inizializzare gli attributi)
    Decompressore();

    // Distruttore (opzionale, usato per rilasciare risorse allocate)
    ~Decompressore();

    void send(std::string a);
    std::string receive();
    void setChannel(std::queue<std::string> ch);
    RSA::PublicKey getPublicKey();
    RSA::PrivateKey getPrivateKey();
    std::string checkIndexesString();
    void createSharedKey(std::string);


private:
    // Attributi privati della classe
    std::string shared_info[5];
    InvertibleRSAFunction params;
    std::queue<std::string> channel;
    byte sharedkey[32];
    int a;
};

#endif  // MYCLASS_H

