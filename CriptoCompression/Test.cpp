#include <iostream>
#include "Compressore.h"
#include "Decompressore.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <queue>
#include <string>


#define DERIVED_KEY_LENGTH 32





int main() {
	Compressore compressore;
	Decompressore decompressore;
	std::queue<std::string> channel;
	
	compressore.setChannel(channel);
	decompressore.setChannel(channel);


	std::string decompressore_indici = decompressore.checkIndexesString();
	channel.push(decompressore_indici);

	std::cout << "Indici del decompressore: " << decompressore_indici << std::endl;

	std::vector<int> indici_comuni = compressore.indexesInCommon(channel.front());

	std::cout << "Indici in comune: " << std::endl;

	for (int i = 0; i < indici_comuni.size(); i++) {
		std::cout << indici_comuni[i] << std::endl;
	}

	channel.pop();

	std::string permutazione_scelta = compressore.permutation(indici_comuni);
	std::cout << permutazione_scelta << std::endl;

	channel.push(permutazione_scelta);

	compressore.createSharedKey(permutazione_scelta);
	//decompressore.createSharedKey(permutazione_scelta);

	byte* chiave_compressore = compressore.getSharedKey();

	std::cout << "Derived Key: ";
	for (size_t i = 0; i < DERIVED_KEY_LENGTH; ++i) {
		std::cout << std::hex << static_cast<int>(chiave_compressore[i]);
	}

	std::cout << std::endl;

	return 0;

}