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

    void setChannel(std::queue<std::string> ch);
    RSA::PublicKey getPublicKey();
    RSA::PrivateKey getPrivateKey();
    byte* getSharedKey();
    std::string checkIndexesString();
    void createSharedKey(std::string);
    std::vector<int> tokenizeByComma(std::string);
    std::string encryptMessageRSA(std::string, RSA::PublicKey);
    std::string decryptMessageRSA(std::string);
    std::string signMessageRSA(const std::string&);
    bool verifySignatureRSA(const std::string& , const std::string& , const RSA::PublicKey&);


private:
    // Attributi privati della classe

    AutoSeededRandomPool rng;
    std::string sharedInfo[5];
    InvertibleRSAFunction params;
    HKDF<SHA256> hkdf;
    std::queue<std::string> channel;

    byte sharedKey[32];
    byte salt[4] = { 0x00, 0x01, 0x02, 0x03 }; // Salt 
    byte info[16] = "Additional Info"; // Additional Info

    const size_t saltLength = sizeof(salt);
    const size_t infoLength = sizeof(info) - 1; // -1 per escludere il terminatore null
    const size_t derivedKeyLength = 32; // Lunghezza della chiave derivata (in byte)
};

#endif  // MYCLASS_H

