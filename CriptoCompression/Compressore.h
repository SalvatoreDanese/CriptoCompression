// Dichiarazione della classe nel file header (es. Compressore.h)

#ifndef COMPRESSORE_H  // Direttiva per l'inclusione condizionale per evitare inclusioni multiple
#define COMPRESSORE_H
#include <string>
#include <iostream>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <queue>
#include <vector>
#include <unordered_map>

#define MAX_SHARED_KNOWLEDGE 20

using namespace CryptoPP;

class Compressore {
public:
    // Membri della classe (attributi e metodi)

    // Costruttore (di solito usato per inizializzare gli attributi)
    Compressore();

    // Distruttore (opzionale, usato per rilasciare risorse allocate)
    ~Compressore();

    void setChannel(std::queue<std:: string> ch);
    RSA::PublicKey getPublicKey();
    RSA::PrivateKey getPrivateKey();
    byte* getSharedKey();
    std::string checkIndexesString();
    std::vector<int> indexesInCommon(std::string);
    std::string createDisposition(std::vector<int>);
    void createSharedKey(std::string);
    std::vector<int> tokenizeByComma(std::string);
    byte* convertToByte(std::string);
    std::string encryptMessageRSA(std::string, RSA::PublicKey);
    std::string decryptMessageRSA(std::string);
    std::string signMessageRSA(const std::string&);
    bool verifySignatureRSA(const std::string&, const std::string&, const RSA::PublicKey&);
    std::string calculateHash(std::string&);
    unsigned int rabin_fingerprint(std::string& text, unsigned int prime = 683303);
    void calculateSharedInfo();
    std::unordered_map<int, std::string> chooseIndexes(int remaining, std::vector<int> &commonIndexes);

    

private:
    // Attributi privati della classe
    AutoSeededRandomPool rng;
    std::unordered_map<int, std::string> sharedInfo;
    InvertibleRSAFunction params;
    HKDF<SHA256> hkdf;
    std::queue<std::string> channel;

    byte sharedKey[256];
    byte salt[4] = { 0x00, 0x01, 0x02, 0x03 }; // Salt 
    byte info[16] = "Additional Info"; // Additional Info

    const size_t saltLength = sizeof(salt);
    const size_t infoLength = sizeof(info) - 1; // -1 per escludere il terminatore null
    const size_t derivedKeyLength = 256; // Lunghezza della chiave derivata (in byte)
    
};

#endif  // MYCLASS_H

