#ifndef HUFFMAN_H // Direttiva per l'inclusione condizionale per evitare inclusioni multiple
#define HUFFMAN_H

#include <iostream>
#include <map>
#include <queue>
#include <bitset>
#include <fstream>  // Per ifstream
#include <vector>  // Per vector
#include <iterator> // Per istreambuf_iterator
#include <string> // Aggiunto per includere la libreria string
#include <sstream>

using namespace std;

// Dichiarazione della classe
class Huffman {
private:
	map<char, string> codes; //Associa ad un simbolo la sua codifica nell'albero
	map<char, int> frequencies;	//Associa ad un simbolo la sua frequenza

	//Chiave segreta, condivisa prima dell'esecuzione tra codificatore e decodificatore
	//2048 bit, in questo caso.
	string key;

	struct Node {	//Rappresenta il nodo all'interno dell'albero
		char data; // Carattere. Per indicare un nodo genitore (non simbolo), si usa il carattere speciale ASCII 0x0c Form Feed, che non dovrebbe comparire mai in un testo normale.
		int freq; // Frequenza del carattere
		Node* left, * right;

		Node(char data, int freq)
		{
			left = right = NULL;
			this->data = data;
			this->freq = freq;
		}
	};

	struct compare	//Serve ad ordinare la priority queue in ordine crescente di frequenza.
	{
		bool operator()(Node* l, Node* r)
		{
			return (l->freq > r->freq);
		}
	};

public:
	// Costruttore
	Huffman(string key);

	// Metodi

	void getCodes(Node* root, string code); //Funzione ricorsiva per caricare i simboli con la loro codifica in codes, in modo da poterli usare per la codifica.

	priority_queue<Node*, vector<Node*>, compare> HuffmanTree; //Priority queue che contiene l'albero di Huffman normale.

	void printHuffmanTree(Node* root); //Stampa l'albero di Huffman in formato con marker

	void printHuffmanTreeNodes(Node* root); //Stampa i nodi dell'albero di Huffman, incontrati con preorder.

	void calcFreq(string inputString);	//Carica in frequencies le frequenze di tutti i caratteri nella stringa in input

	void reCalcFreq(Node* node);	//ricalcola la frequenza di tutti i nodi nell'albero, serve ad individuare i genitori correttamente nell'albero.

	void addKLeaves(Node* root, vector<Node*>* storage, int* k, string key, int searchedBit);	//Usato per kTransformations, aggiunge k foglie in storage.

	void addHuffmanTreeLeaves(Node* root, vector<Node*>* storage);	//Usato per bulkTransformations, aggiunge tutte le foglie a storage.

	void buildHuffmanTree(int size);	//Costruisce l'albero di Huffman e lo carica in HuffmanTree.

	void saveHuffmanTree(Node* root, string& output); //Funzione ricorsiva per codificare un'albero di huffman come stringa. Alla fine dell'esecuzione, output lo conterrà.

	void writeToBin(string filename, string inputString); //Permette di scrivere dentro al file fornito la rappresentazione in binario della stringa str, effettuando padding. Presuppone che il file sia stato aperto in modalità di scrittura binaria.

	string readFromBin(string filename);	//Legge da un file binario il contenuto, rimuove il padding e lo restituisce come stringa.

	string applyOneTimePad(string data, string key); //Esegue codifica di data usando key come One Time Pad. Presuppone che data e key siano stringhe binarie, e che key >= data.

	void storeHuffmanTree(struct Node* root, string filename);		//Funzione ricorsiva per salvare su file  binario l'albero di decodifica

	void storeSecureHuffmanTree(struct Node* root, string filename, string key);	//Funzione ricorsiva per salvare su file binario l'albero di decodifica, criptato usando key come One Time Pad.

	Node* rebuildHuffmanTree(string& encodedString);

	string decodeString(Node* root, string encodedString);	//Decodifica la stringa usando l'albero di decodifica

	void mirror(Node* node);	//Funzione ricorsiva per cambiare un sott'albero nella sua versione "allo specchio".

	//Servono due funzioni di ricerca genitore, in quanto il nodo che richiede la ricerca potrebbe essere un genitore, quindi la ricerca per simbolo non funziona.

	Node* findParentFromSymbol(Node* node, char symbol); //Funzione ricorsiva per trovare il genitore del nodo searched. 

	Node* findParentFromNode(Node* node, Node* searched);	//Funzione ricorsiva per trovare il genitore del nodo searched.

	void swapChildren(Node* node); //Scambia di posto il figlio sinistro di node con il destro e viceversa.

	void swap(Node* root, char symbol); //Scambia di posto root con l'altro figlio del suo genitore.

	Node* nextRight(Node* root, char symbol); //Restituisce il nodo a destra di quello symbol: se non esiste, restituisce quello più a sinistra sul suo livello.

	void swap(Node* parent1, Node* parent2, Node* node1, Node* node2);

	void levelSwap(Node* root, char symbol);

	void transformationCoding(int transformation, Node* root, char symbol);	//Gestisce le trasformazioni da eseguire sul BST

	string getConvertedKey(string key, int* k);

	void runKTransformations(Node* root, string key, int k);

	void runBulkTransformations(Node* root, string key);

	void huffmanEncode(string filename, string extension, int transformationMethod, int numDC);	//Effettua codifica di Huffman

	void huffmanDecode(string filename, string key);	//Effettua la decodifica e salva il testo decodificato come una stringa nel file <nomefile> decoded.txt

};

#endif // MYCLASS_H
