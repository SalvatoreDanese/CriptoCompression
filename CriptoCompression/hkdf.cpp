#include <iostream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>

using namespace CryptoPP;

void DeriveKeyWithHKDF(const byte* salt, size_t saltLength,
    const byte* ikm, size_t ikmLength,
    const byte* info, size_t infoLength,
    byte* derivedKey, size_t derivedKeyLength) {
    HKDF<SHA256> hkdf;
    hkdf.DeriveKey(derivedKey, derivedKeyLength, ikm, ikmLength, salt, saltLength, info, infoLength);
}

int funzione2() {
    // Definizione dei parametri per la derivazione di chiavi
    byte salt[] = { 0x00, 0x01, 0x02, 0x03 }; // Salt (puoi generare casualmente) HASH DELLE COSE CHE DOBBIAMO FA
    byte ikm[] = "Input Key Material"; // Input Key Material 
    byte info[] = "Additional Info"; // Additional Info

    const size_t saltLength = sizeof(salt);
    const size_t ikmLength = sizeof(ikm) - 1; // -1 per escludere il terminatore null
    const size_t infoLength = sizeof(info) - 1; // -1 per escludere il terminatore null
    const size_t derivedKeyLength = 32; // Lunghezza della chiave derivata (in byte)

    byte derivedKey[derivedKeyLength];

    // Esecuzione della derivazione di chiavi con HKDF
    DeriveKeyWithHKDF(salt, saltLength, ikm, ikmLength, info, infoLength, derivedKey, derivedKeyLength);

    // Stampa della chiave derivata
    std::cout << "Derived Key: ";
    for (size_t i = 0; i < derivedKeyLength; ++i) {
        std::cout << std::hex << static_cast<int>(derivedKey[i]);
    }
    std::cout << std::endl;

    return 0;
}