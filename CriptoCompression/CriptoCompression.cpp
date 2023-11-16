#include <iostream>
#include <chrono>

#include "cryptopp/cryptlib.h"
#include "cryptopp/sha3.h"
#include "cryptopp/rsa.h"
#include "cryptopp/hkdf.h"
#include "cryptopp/hex.h"


std::string sha3(std::string& input) {
    CryptoPP::SHA3_256 hash;

    std::string digest;
    std::string output;

    CryptoPP::StringSource(input, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::StringSink(digest)
        ) //HashFilter
    ); //StringSource

    CryptoPP::StringSource(digest, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(output)
        )
    ); //StringSource

    return output;
}

int main() {
    std::string msg1 = "Lorem ipsum dolor sit amet conse";
    std::string msg2 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim,";
    std::string msg3 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, m";
    std::string msg4 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur";
    std::string msg5 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exerci";
    std::string digest;



    for (int i = 0; i < 1000; i++) {
        digest = sha3(msg1);
    }

    std::cout << "Message: " << msg1 << std::endl;
    std::cout << "Digest: " << digest << std::endl;



    for (int i = 0; i < 1000; i++) {
        digest = sha3(msg2);
    }
    std::cout << "Message: " << msg2 << std::endl;
    std::cout << "Digest: " << digest << std::endl;


    for (int i = 0; i < 1000; i++) {
        digest = sha3(msg3);
    }

    std::cout << "Message: " << msg3 << std::endl;
    std::cout << "Digest: " << digest << std::endl;



    for (int i = 0; i < 1000; i++) {
        digest = sha3(msg4);
    }

    std::cout << "Message: " << msg4 << std::endl;
    std::cout << "Digest: " << digest << std::endl;



    for (int i = 0; i < 1000; i++) {
        digest = sha3(msg5);
    }

    std::cout << "Message: " << msg5 << std::endl;
    std::cout << "Digest: " << digest << std::endl;
    return 0;
}