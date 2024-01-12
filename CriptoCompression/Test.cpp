#include <iostream>
#include "Compressore.h"
#include "Decompressore.h"
#include "Huffman.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <queue>
#include <string>
#include <bitset>


#define DERIVED_KEY_LENGTH 256



void printMessage(std::string message, std::string sender) {
	std::cout << "[" << sender << "] " << message << std::endl << std::endl;
}




int main() {
	Compressore compressor;
	Decompressore decompressor;
	std::queue<std::string> channel;
	
	compressor.setChannel(channel);
	decompressor.setChannel(channel);

	compressor.calculateSharedInfo();
	decompressor.calculateSharedInfo();
	

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
	int remaining;
	std::unordered_map<int, std::string> missingIndexes;

	if (commonIndexes.size() < 5) {
		
		remaining = 5 - commonIndexes.size();

		missingIndexes = compressor.chooseIndexes(remaining, commonIndexes);

		for (int i = 0; i < missingIndexes.size(); i++) {
			if (!missingIndexes[i].empty()) {
				std::string encryptedMissingInfo = compressor.encryptMessageRSA("SYNC - " + std::to_string(i) + ":" + missingIndexes[i], decompressor.getPublicKey());
				std::string encryptedMissingInfoSignature = compressor.signMessageRSA(encryptedMissingInfo);

				channel.push(encryptedMissingInfo);
				channel.push(encryptedMissingInfoSignature);

				printMessage("ENCRYPTED SYNCH: \n" + encryptedMissingInfo, "COMPRESSOR");
				printMessage("ENCRYPTED SYNCH SIGNATURE: \n" + encryptedMissingInfo, "COMPRESSOR");


				std::string encryptedSynch = channel.front();
				channel.pop();

				std::string encryptedSynchSignature = channel.front();
				channel.pop();

				if (!decompressor.verifySignatureRSA(encryptedSynch, encryptedSynchSignature, compressor.getPublicKey())) {
					std::cout << "MESSAGE NOT AUTHENTICATED!" << std::endl;
					return 0;
				}
				std::string decryptedSynch = decompressor.decryptMessageRSA(encryptedSynch);

				decompressor.processMessage(decryptedSynch);
				
			}
			
		}

		//SYNC --- fing1 -> hash1 ...
		//DISPOSITION OF FING...
	
	}


	std::string choosenDisposition = compressor.createDisposition(commonIndexes);

	std::string encryptedChoosenDisposition = compressor.encryptMessageRSA(choosenDisposition, decompressor.getPublicKey());

	channel.push(encryptedChoosenDisposition);

	std::string encryptedChoosenDispositionSignature = compressor.signMessageRSA(encryptedChoosenDisposition);
	channel.push(encryptedChoosenDispositionSignature);

	printMessage("ENCRYPTED CHOOSEN DISPOSITION INDEXES:\n" + encryptedChoosenDisposition, "COMPRESSOR");
	printMessage("ENCRYPTED CHOOSEN DISPOSITION INDEXES SIGNATURE:\n" + encryptedChoosenDispositionSignature, "COMPRESSOR");
	std::cout << std::endl << "END CHANNEL TRANSCRIPT: " << std::endl << "**************************"  <<  std::endl;

	std::string encryptedChoosenDispositionByCompressor = channel.front();
	channel.pop();

	std::string encryptedChoosenDispositionSignatureByCompressor = channel.front();
	channel.pop();


	if (!decompressor.verifySignatureRSA(encryptedChoosenDispositionByCompressor, encryptedChoosenDispositionSignatureByCompressor, compressor.getPublicKey())) {
		std::cout << "MESSAGE NOT AUTHENTICATED!" << std::endl;
		return 0;
	}

	std::string decryptedChoosenDisposition = decompressor.decryptMessageRSA(encryptedChoosenDispositionByCompressor);

	compressor.createSharedKey(choosenDisposition);
	decompressor.processMessage(decryptedChoosenDisposition);

	byte* compressorSymKey = compressor.getSharedKey();
	byte* decompressorSymKey = decompressor.getSharedKey();


	std::cout << std::endl << "**************************" << std::endl << "PLAINTEXT DATA FLOW: " << std::endl << std::endl;

	

	printMessage("Decompressor indexes: " + decompressorIndexes, "DECOMPRESSOR");

	std::cout << "COMMON INDEXES: ";
	for (int i = 0; i < commonIndexes.size(); i++) {
		std::cout << commonIndexes[i] << ",";
	}
	std::cout << std::endl << std::endl;

	printMessage("Choosen disposition:\n" + choosenDisposition, "COMPRESSOR");
	printMessage("Decrypted choosen disposition: " + decryptedChoosenDisposition, "DECOMPRESSOR");

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


	// Converti l'array di byte in una stringa binaria
	std::string binaryString = "";
	for (int i = 0; i <DERIVED_KEY_LENGTH; ++i) {
		binaryString += std::bitset<8>(compressorSymKey[i]).to_string();
	}

	// Stampa la stringa binaria risultante
	std::cout << "Stringa binaria risultante: " << binaryString << std::endl;


	Huffman h(binaryString);
	
	h.huffmanEncode("bible", ".txt", 2, 400);
	
	std::string dbinaryString = "";
	for (int i = 0; i < DERIVED_KEY_LENGTH; ++i) {
		dbinaryString += std::bitset<8>(decompressorSymKey[i]).to_string();
	}

	h.huffmanDecode("bible",dbinaryString);

	return 0;

}

