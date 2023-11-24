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



void printMessage(std::string message, std::string sender) {
	std::cout << "[" << sender << "] " << message << std::endl << std::endl;
}


int main() {
	Compressore compressor;
	Decompressore decompressor;
	std::queue<std::string> channel;
	
	compressor.setChannel(channel);
	decompressor.setChannel(channel);

	std::cout << "**************************" << std::endl << "CHANNEL TRANSCRIPT: " << std::endl << std::endl;


	std::string decompressorIndexes = decompressor.checkIndexesString();
	std::string encryptedDecompressorIndexes = decompressor.encryptMessageRSA(decompressorIndexes, compressor.getPublicKey());
	

	std::string decompressorIndexesSignature = decompressor.signMessageRSA(encryptedDecompressorIndexes);

	channel.push(encryptedDecompressorIndexes);
	channel.push(decompressorIndexesSignature);

	printMessage("ENCRYPTED DECOMPRESSOR INDEXES:\n" +encryptedDecompressorIndexes, "DECOMPRESSOR");
	printMessage("ENCRYPTED DECOMPRESSOR INDEXES SIGNATURE:\n" + decompressorIndexesSignature, "DECOMPRESSOR");

	

	
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

	std::string choosenPermutation = compressor.createPermutation(commonIndexes);

	std::string encryptedChoosenPermutation = compressor.encryptMessageRSA(choosenPermutation, decompressor.getPublicKey());

	channel.push(encryptedChoosenPermutation);

	std::string encryptedChoosenPermutationSignature = compressor.signMessageRSA(encryptedChoosenPermutation);
	channel.push(encryptedChoosenPermutationSignature);

	printMessage("ENCRYPTED CHOOSEN PERMUTATION INDEXES:\n" + encryptedChoosenPermutation, "COMPRESSOR");
	printMessage("ENCRYPTED CHOOSEN PERMUTATION INDEXES SIGNATURE:\n" + encryptedChoosenPermutationSignature, "COMPRESSOR");
	std::cout << std::endl << "END CHANNEL TRANSCRIPT: " << std::endl << "**************************"  <<  std::endl;

	std::string encryptedChoosenPermutationByCompressor = channel.front();
	channel.pop();

	std::string encryptedChoosenPermutationSignatureByCompressor = channel.front();
	channel.pop();


	if (!decompressor.verifySignatureRSA(encryptedChoosenPermutationByCompressor, encryptedChoosenPermutationSignatureByCompressor, compressor.getPublicKey())) {
		std::cout << "MESSAGE NOT AUTHENTICATED!" << std::endl;
		return 0;
	}

	std::string decryptedChoosenPermutation = decompressor.decryptMessageRSA(encryptedChoosenPermutationByCompressor);

	compressor.createSharedKey(choosenPermutation);
	decompressor.createSharedKey(decryptedChoosenPermutation);

	byte* compressorSymKey = compressor.getSharedKey();
	byte* decompressorSymKey = decompressor.getSharedKey();


	std::cout << std::endl << "**************************" << std::endl << "PLAINTEXT DATA FLOW: " << std::endl << std::endl;

	
	printMessage("Decompressor indexes: " + decompressorIndexes, "DECOMPRESSOR");

	std::cout << "COMMON INDEXES: ";
	for (int i = 0; i < commonIndexes.size(); i++) {
		std::cout << commonIndexes[i] << ",";
	}
	std::cout << std::endl << std::endl;

	printMessage("Choosen permutation:\n" + choosenPermutation, "COMPRESSOR");
	printMessage("Decrypted choosen permutation: " + decryptedChoosenPermutation, "DECOMPRESSOR");

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

