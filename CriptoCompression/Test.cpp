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
	Compressore compressor;
	Decompressore decompressor;
	std::queue<std::string> channel;
	
	compressor.setChannel(channel);
	decompressor.setChannel(channel);


	std::string decompressorIndexes = decompressor.checkIndexesString();
	std::string encryptedDecompressorIndexes = decompressor.encryptMessageRSA(decompressorIndexes, compressor.getPublicKey());
	

	std::cout << "Decompressor indexes: " << decompressorIndexes << std::endl;

	std::string decompressorIndexesSignature = decompressor.signMessageRSA(encryptedDecompressorIndexes);

	channel.push(encryptedDecompressorIndexes);
	channel.push(decompressorIndexesSignature);

	std::cout << "SIGNATURE decompressor indexes: " << decompressorIndexesSignature << std::endl;

	
	std::string encryptedIndexesByDecompressor = channel.front();
	channel.pop();

	std::string encryptedIndexesSignatureByDecompressor = channel.front();
	channel.pop();

	if (!compressor.verifySignatureRSA(encryptedIndexesByDecompressor, encryptedIndexesSignatureByDecompressor, decompressor.getPublicKey())) {
		std::cout << "MESSAGE NOT AUTHENTICATED!" << std::endl;
		return 0;
	}



	std::string decryptedDecompressorIndexes = compressor.decryptMessageRSA(encryptedDecompressorIndexes);

	std::vector<int> commonIndexes = compressor.indexesInCommon(decryptedDecompressorIndexes);


	std::cout << "Common indexes: ";

	for (int i = 0; i < commonIndexes.size(); i++) {
		std::cout << commonIndexes[i] << ",";
	}
	std::cout << std::endl;


	std::string choosenPermutation = compressor.createPermutation(commonIndexes);
	std::cout <<"Choosen permutation: " << choosenPermutation << std::endl;

	std::string encryptedChoosenPermutation = compressor.encryptMessageRSA(choosenPermutation, decompressor.getPublicKey());

	std::cout << "Encrypted choosen permutation: " << encryptedChoosenPermutation << std::endl;


	channel.push(encryptedChoosenPermutation);

	std::string encryptedChoosenPermutationSignature = compressor.signMessageRSA(encryptedChoosenPermutation);
	channel.push(encryptedChoosenPermutationSignature);


	std::string encryptedChoosenPermutationByCompressor = channel.front();
	channel.pop();

	std::string encryptedChoosenPermutationSignatureByCompressor = channel.front();
	channel.pop();


	if (!decompressor.verifySignatureRSA(encryptedChoosenPermutationByCompressor, encryptedChoosenPermutationSignatureByCompressor, compressor.getPublicKey())) {
		std::cout << "MESSAGE NOT AUTHENTICATED!" << std::endl;
		return 0;
	}

	std::string decryptedChoosenPermutation = decompressor.decryptMessageRSA(encryptedChoosenPermutationByCompressor);

	

	std::cout << "Decrypted choosen permutation: " << decryptedChoosenPermutation << std::endl;

	compressor.createSharedKey(choosenPermutation);
	decompressor.createSharedKey(decryptedChoosenPermutation);

	byte* compressorSymKey = compressor.getSharedKey();
	byte* decompressorSymKey = decompressor.getSharedKey();

	std::cout << "[COMPRESSOR] Derived Key: ";
	for (size_t i = 0; i < DERIVED_KEY_LENGTH; ++i) {
		std::cout << std::hex << static_cast<int>(compressorSymKey[i]);
	}

	std::cout << std::endl;

	std::cout << "[DECOMPRESSOR] Derived Key: ";
	for (size_t i = 0; i < DERIVED_KEY_LENGTH; ++i) {
		std::cout << std::hex << static_cast<int>(decompressorSymKey[i]);
	}

	std::cout << std::endl;

	return 0;

}