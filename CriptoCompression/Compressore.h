// Dichiarazione della classe nel file header (es. Compressore.h)

#ifndef COMPRESSORE_H  // Direttiva per l'inclusione condizionale per evitare inclusioni multiple
#define COMPRESSORE_H
#include <string>
#include <iostream>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <queue>

using namespace CryptoPP;

class Compressore {
public:
    // Membri della classe (attributi e metodi)

    // Costruttore (di solito usato per inizializzare gli attributi)
    Compressore();

    // Distruttore (opzionale, usato per rilasciare risorse allocate)
    ~Compressore();

    void send(std:: string a);
    std::string receive(std:: string a);
    void setChannel(std::queue<std:: string> ch);
private:
    // Attributi privati della classe
    std::string shared_info[5];
    InvertibleRSAFunction params;
    std::queue<std::string> channel;
    byte* sharedkey;
};

#endif  // MYCLASS_H

