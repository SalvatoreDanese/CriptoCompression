#include "Huffman.h"

// Implementazione dei metodi della classe Huffman

// Alcuni metodi potrebbero richiedere l'implementazione di funzioni ausiliarie
// che non sono definite nel tuo header. Assicurati di implementarle se necessario.

Huffman::Huffman(string key) {
	this->key = key;
}

void Huffman::getCodes(Node* root, string code) {
	if (root == NULL)	//Caso base
	{
		return;
	}
	if (root->data != 0x0c)	//Se è una foglia:
	{
		codes[root->data] = code;
	}
	getCodes(root->left, code + "0");
	getCodes(root->right, code + "1");
}

void Huffman::printHuffmanTree(Node* root) {
	if (root)
	{

		if (root->left || root->right)
		{
			cout << "0";
		}
		else
		{
			cout << "1" << root->data;
		}
		printHuffmanTree(root->left);
		printHuffmanTree(root->right);
	}
}

void Huffman::printHuffmanTreeNodes(Node* root) {
	if (root)
	{
		cout << "Nodo incontrato: " << root->data << " frequenza: " << root->freq << endl;
		printHuffmanTreeNodes(root->left);
		printHuffmanTreeNodes(root->right);
	}
}

void Huffman::calcFreq(string inputString) {
	for (int i = 0; i < inputString.length(); i++)	//Attraversa la stringa
	{
		frequencies[inputString[i]] = frequencies[inputString[i]] + 1;	//Incrementa la frequenza del carattere in posizione i
	}
}

void Huffman::reCalcFreq(Node* node) {
	if (node)
	{
		reCalcFreq(node->left);
		reCalcFreq(node->right);
		if (node->left != NULL && node->right != NULL)	//Se non è una foglia
		{
			node->freq = node->left->freq + node->right->freq;
		}
	}
}

void Huffman::addKLeaves(Node* root, vector<Node*>* storage, int* k, string key, int searchedBit) {
	if (root && *k > 0) //Attraversa l'albero
	{
		int bitCurr = key[0] - '0';
		key.erase(key.begin());
		if (bitCurr == searchedBit)	//Se incontra un 1 nella chiave ed il nodo corrente è una foglia, lo aggiunge.
		{
			if (root->left == NULL && root->right == NULL)
			{
				storage->push_back(root);
				float chance = (float)rand() / RAND_MAX;
				if (chance > 0.5)
				{
					if (searchedBit == 0)
					{
						searchedBit = 1;
					}
					else
					{
						searchedBit = 0;
					}
				}
				*k = *k - 1;
			}
		}
		addKLeaves(root->left, storage, k, key, searchedBit);
		addKLeaves(root->right, storage, k, key, searchedBit);
	}
}

void Huffman::addHuffmanTreeLeaves(Node* root, vector<Node*>* storage) {
	if (root)
	{
		addHuffmanTreeLeaves(root->left, storage);
		addHuffmanTreeLeaves(root->right, storage);
		if (root->left == NULL && root->right == NULL)
		{
			storage->push_back(root);
		}
	}
}

void Huffman::buildHuffmanTree(int size) {
	Node* node;
	for (pair<char, int> element : frequencies)
	{
		HuffmanTree.push(new Node(element.first, element.second));	//Simbolo, frequenza
	}
	while (HuffmanTree.size() > 1) //Finchè ci sono almeno due sottalberi
	{
		node = new Node(0x0c, 0);	//Crea un nuovo sottalbero, con figlio sinistro il primo sottalbero e destro il secondo, peso è la loro somma.
		node->left = HuffmanTree.top();
		HuffmanTree.pop();
		node->right = HuffmanTree.top();
		HuffmanTree.pop();
		node->freq = node->left->freq + node->right->freq;
		HuffmanTree.push(node);
	}
}

void Huffman::saveHuffmanTree(Node* root, string& output) {
	if (root)
	{
		if (root->left || root->right) //Se è foglia, carattere precedente (marker)  sarà 0, 1 se è genitore.
		{
			output += "0";
		}
		else
		{
			output += "1";
			output += bitset<8>(root->data).to_string();	//Se è un simbolo, per scriverlo su file binario devo convertirlo in binario, e in decodifica riconvertirlo in carattere.
		}
		saveHuffmanTree(root->left, output);
		saveHuffmanTree(root->right, output);
	}
}

void Huffman::writeToBin(string filename, string inputString) {
	//Formato di scrittura: <binario della stringa + bit 0 di padding necessari a formare un numero di bit multiplo di 8 + 1 byte, rappresentazione binaria di un int che rappresenta il numero di zeri di padding inseriti>

	ofstream fbinwrite(filename, ios::binary);

	vector<unsigned char> buffer;

	for (char c : inputString)
	{
		int curr_bit = c - '0';	//Prende un singolo bit alla volta.
		buffer.push_back(curr_bit);	//Lo aggiunge al buffer
		if (buffer.size() == 8) 	//Se ho 8 bit, forma un byte.
		{
			unsigned char byte = 0;
			for (int i = 0; i < 8; i++)
			{
				byte |= (buffer[i] << (7 - i));	//Inserisce ogni bit nel byte.
			}
			fbinwrite.write(reinterpret_cast<char*>(&byte), sizeof(unsigned char)); // Scrive il byte su file
			buffer.clear();
		}
	}

	unsigned char byte = 0;	//Reset del buffer di byte
	// Se l'insieme di bit non era multiplo di 8, necessario inserire il resto ed il padding:
	if (!buffer.empty())
	{
		for (int i = 0; i < buffer.size(); i++)	//Inserisce i bit rimanenti nel byte
		{
			byte |= (buffer[i] << (7 - i));
		}
		// Zeri di padding vanno inseriti davanti al valore reale, non dopo, altrimenti si altera il significato.
		byte >>= (8 - buffer.size());
		fbinwrite.write(reinterpret_cast<char*>(&byte), sizeof(unsigned char));
	}

	//Inserisce il byte contenente il numero di zeri di padding aggiunti.
	byte = 0;
	if (buffer.empty())	/*Nel caso in cui non abbiamo zeri di padding da aggiungere, si inserisce lo stesso il byte di conto con valore 0 per permettere la decodifica.*/
	{
		byte <<= 0;
	}
	else
	{
		byte |= (8 - buffer.size());	//Aggiunge un byte contenente il numero di zeri aggiunti
	}
	fbinwrite.write(reinterpret_cast<char*>(&byte), sizeof(unsigned char));

	fbinwrite.close();
}

string Huffman::readFromBin(string filename) {
	string decodedString;

	ifstream fbinread(filename, ios::binary);	//Apre il file binario
	vector<unsigned char> binbuf(istreambuf_iterator<char>(fbinread), {});	//Iteratore sul file

	vector<int> decodevector;	//Buffer per i bit
	int num_padding = 0;	//Contiene il numero di zeri di padding inseriti, ricavati dall'ultimo byte
	string padString;	//Contiene il byte di conto padding

	for (unsigned char c : binbuf) 	//Converte la stringa nel vettore binario corrispondente
	{
		for (int i = 7; i >= 0; i--)
		{
			int curr_bit = (c >> i) & 1;
			decodevector.push_back(curr_bit);
		}
	}
	int numBytes = decodevector.size() / 8;

	//Calcola i bit di padding dall'ultimo byte.
	for (int j = 0; j < 8; j++)
	{
		padString += to_string(decodevector[(numBytes - 1) * 8 + j]);
	}
	num_padding = stoi(padString, 0, 2);
	numBytes = numBytes - 1;	//Bisogna ignorare il byte di conto padding dal totale.

	for (int i = 0; i < 8; i++)	//Rimuove l'ultimo byte
	{
		decodevector.pop_back();
	}

	for (int i = 0; i < num_padding; i++)	//Rimuove i bit di padding dal penultimo byte.
	{
		decodevector.erase(decodevector.begin() + (decodevector.size() - 8) + i);
	}

	for (auto element : decodevector)	//Ricava la stringa originale
	{
		decodedString += to_string(element);
	}
	fbinread.close();

	return decodedString;
}

string Huffman::applyOneTimePad(string data, string key) {
	//cout << "Dati OTP: " << data << endl;
	//cout << "Chiave OTP: " << key << endl;

	string result = "";

	if (key.length() < data.length())
	{
		cout << "ERRORE: La chiave segreta scelta ha dimensioni insufficienti per la codifica One Time Pad. Riprovare con una chiave di almeno " << data.length() << " bit." << endl;
		exit(1);	//Termina l'esecuzione del programma
	}

	for (int i = 0; i < data.length(); i++)	//Esegue XOR bit per bit tra data e key, risultato si trova in result.
	{
		if (data[i] == key[i])
		{
			result.push_back('0');
		}
		else result.push_back('1');
	}
	//cout << "Risultato OTP: " << result << endl;
	return result;
}

void Huffman::storeHuffmanTree(struct Node* root, string filename) {
	string tree = "";
	saveHuffmanTree(root, tree);
	string name = filename + " tree.bin";
	writeToBin(name, tree);
}

void Huffman::storeSecureHuffmanTree(struct Node* root, string filename, string key) {
	string tree = "";
	saveHuffmanTree(root, tree);
	string secureTree = applyOneTimePad(tree, key);
	string name = filename + " tree.bin";
	writeToBin(name, secureTree);
}

Huffman::Node* Huffman::rebuildHuffmanTree(string& encodedString) {
	if (encodedString.empty()) //Caso base
	{
		return nullptr;
	}

	char firstChar = encodedString[0];	//Carattere marker, 0 oppure 1.
	encodedString = encodedString.substr(1); // Rimuove il carattere marker

	if (firstChar == '1')
	{
		// Indica che il carattere successivo è un simbolo, crea quindi un nodo foglia con quel valore.
		char value = encodedString[0];
		if (encodedString.length() == 0)	//Gestisce il caso eccezionale in cui l'ultimo carattere è whitespace.
		{

		}
		else
		{
			encodedString = encodedString.substr(1); // Rimuove il simbolo
		}
		return new Node(value, 0);	//Crea la foglia
	}

	else
	{
		//0, quindi questo nodo è un genitore. Lo crea, ed usa la ricursione per assegnargli figlio sinistro e destro.
		Node* left = rebuildHuffmanTree(encodedString);
		Node* right = rebuildHuffmanTree(encodedString);
		Node* temp = new Node(0x0c, 0);	//Il genitore
		temp->left = left;
		temp->right = right;
		return temp;
	}
}

string Huffman::decodeString(Node* root, string encodedString) {
	string decodedString = "";	//La stringa decodificata
	Node* curr = root; // Il nodo corrente

	for (int i = 0; i < encodedString.length(); i++) //Attraversa la stringa codificata
	{
		if (encodedString[i] == '0')	//Va a sinistra
		{
			curr = curr->left;
		}
		else
		{
			curr = curr->right; //Va a destra
		}
		if (curr->left == NULL && curr->right == NULL)	//Se il nodo dove siamo adesso è una foglia, allora è un simbolo, ne legge la codifica.
		{
			//cout << "Valore del carattere " << curr->data << " : " << int(curr->data) << endl;
			if (int(curr->data) < 0) //Vuol dire che questo era uno dei caratteri a cui è stato sottratto il carattere DC, bisogna riprendere quello originale.
			{
				//cout << "Carattere codificato contro CPA individuato: " << curr->data << endl;
				curr->data = int(curr->data) + int(0x7F);
				//cout << "Ricodificato carattere originale : " << curr->data << endl;
			}
			decodedString += curr->data;
			curr = root;	//Resetta il nodo corrente tornando alla radice
		}
	}
	return decodedString;
}

void Huffman::mirror(Node* node) {
	if (node == NULL)	//Caso base
	{
		return;
	}
	else
	{
		Node* temp;
		mirror(node->left);
		mirror(node->right);
		temp = node->left;
		node->left = node->right;
		node->right = temp;
	}
}

Huffman::Node* Huffman::findParentFromSymbol(Node* node, char symbol) {
	if (node->left == NULL && node->right == NULL)
	{
		return NULL;
	}

	if (node->left->data == symbol || node->right->data == symbol)
	{
		return node;
	}
	Node* left = findParentFromSymbol(node->left, symbol);	//Se non l'ha trovato, cerca a sinistra.
	if (left != NULL)
	{
		return left;
	}
	else return findParentFromSymbol(node->right, symbol);	//Cerca a destra se non c'era neanche a sinistra.
}

Huffman::Node* Huffman::findParentFromNode(Node* node, Node* searched) {
	if (node->left == NULL && node->right == NULL)	//Caso base, nodo corrente è una foglia: non possiamo cercare ulteriormente.
	{
		return NULL;
	}

	if (node->left == searched || node->right == searched)
	{
		return node;
	}
	Node* left = findParentFromNode(node->left, searched);	//Se non l'ha trovato, cerca a sinistra.
	if (left != NULL)
	{
		return left;
	}
	else return findParentFromNode(node->right, searched);	//Cerca a destra se non c'era neanche a sinistra.
}

void Huffman::swapChildren(Node* node) {
	if (node->left != NULL && node->right != NULL) //Controlla che esistano, altrimenti segfault
	{
		Node* temp = node->left;
		node->left = node->right;
		node->right = temp;
	}
}

void Huffman::swap(Node* root, char symbol) {
	Node* parent = findParentFromSymbol(root, symbol);
	if (parent != NULL)
	{
		swapChildren(parent);
	}
}

Huffman::Node* Huffman::nextRight(Node* root, char symbol) {
	if (root == NULL) //Caso base
	{
		return 0;
	}

	Node* leftmost=NULL; //Restituito nel caso in cui root sia il nodo più a destra.
	int oldLevel = 1;

	queue<Node*> qn;
	queue<int> ql;
	int level = 1;

	qn.push(root);
	ql.push(level);

	while (!(qn.empty()))
	{
		Node* node = qn.front();
		level = ql.front();

		qn.pop();
		ql.pop();

		if (oldLevel < level)	//Nuovo livello, prendo il leftmost.
		{
			leftmost = node;
		}
		oldLevel = level;

		// Controlla che il nodo corrente sia quello fornito, in tal caso trova quello più a destra. Controlliamo che non sia la radice.
		if (node->data == symbol && level > 1)
		{
			if (ql.front() != level || ql.size() == 0) //Se è il nodo più a destra, restituisce il nodo più a sinistra
			{
				return leftmost;
			}

			//Nessuna delle altre condizioni, quindi restituisce il nodo alla sua destra.
			return qn.front();
		}

		if (node->left != NULL)
		{
			qn.push(node->left);
			ql.push(level + 1);
		}
		if (node->right != NULL)
		{
			qn.push(node->right);
			ql.push(level + 1);
		}
	}
}

void Huffman::swap(Node* parent1, Node* parent2, Node* node1, Node* node2) {
	if (parent1 == parent2) 	//Stesso genitore, quindi sinistro diventa destro e viceversa.
	{
		parent1->left = node2;
		parent1->right = node1;
	}
	else //Genitori diversi.
	{
		if (parent1->left == node1)
		{
			parent1->left = node2;
		}
		else
		{
			parent1->right = node2;
		}

		if (parent2->left == node2)
		{
			parent2->left = node1;
		}
		else
		{
			parent2->right = node1;
		}
	}
}

void Huffman::levelSwap(Node* root, char symbol) {

	Node* node2;	//Il nodo prossimo da scambiare

	node2 = nextRight(root, symbol);

	Node* parent1 = findParentFromSymbol(root, symbol);	//Trova il genitore di quello di cui cerchiamo lo swap
	Node* parent2 = findParentFromNode(root, node2);
	Node* node1;	// Il nodo originale da scambiare

	if (parent1->left->data == symbol)			//Cerca poi il figlio in base a se è sinistro o destro per ottenere il nodo da sostituire
	{
		node1 = parent1->left;
	}
	else node1 = parent1->right;

	swap(parent1, parent2, node1, node2); //Fa lo scambio
}

void Huffman::transformationCoding(int transformation, Node* root, char symbol) {

	//cout << "Trasformazione da eseguire: " << transformation << endl;

	switch (transformation)
	{
	case 0:
		mirror(findParentFromSymbol(root, symbol));
		break;
	case 1:
		swap(root, symbol);
		break;
	case 2:
		levelSwap(root, symbol);
		break;
	default:
		cout << "Errore, indicata trasformazione inesistente" << endl;
	}
}

string Huffman::getConvertedKey(string key, int* k) {
	if (*k > frequencies.size() - 1)
	{
		//cout << "Errore: k inserito è maggiore della dimensione dell'alfabeto. Impostato k al valore massimo possibile." << endl;
		*k = frequencies.size() - 1;
	}

	string sKey;	//La chiave restituita

	int diff = key.length() - (*k * (frequencies.size() / 2));

	if (diff == 0)		//Lunghezza è uguale a quella desiderata
	{
		sKey = key;
	}
	else
	{
		if (diff > 0)	//Lunghezza maggiore di quella desiderata
		{
			sKey = key.substr(0, key.length() - diff);	//Tronca
		}
		else
		{
			sKey = key;
			while (diff < 0)	//Raddoppia invertendo i bit
			{
				for (char ch : sKey)
				{
					if (ch == '0')
					{
						sKey.push_back('1');
					}
					else sKey.push_back('0');
				}
				diff = sKey.length() - (*k * (frequencies.size() / 2)); //Necessario ricalcolare diff per uscire dal ciclo
			}
			if (diff >= 0)	//Tronca quello che avanza
			{
				sKey = sKey.substr(0, sKey.length() - diff);
			}
		}
	}

	return sKey;
}

void Huffman::runKTransformations(Node* root, string key, int k) {
	string sKey = getConvertedKey(key, &k);
	string remKey;

	int diff = sKey.length() - (k * (frequencies.size() / 2));

	if (diff == 0)	//Se non avanza nulla dalla chiave convertita rispetto a quanto ci serve per scegliere i k nodi.
	{
		remKey = sKey;
	}
	else
	{
		remKey = sKey.substr(sKey.length() - diff, sKey.length());
	}
	vector<Node*> chosenNodes;
	int counter = 0;		//Numero di foglie da aggiungere, passato per riferimento.
	int startingBit = 0;	//Valore iniziale del bit che deve corrispondere a quello di K.

	for (int i = 0; i < frequencies.size(); i++)
	{
		counter = k;
		chosenNodes.clear();
		addKLeaves(root, &chosenNodes, &counter, remKey, startingBit);

		//Inverte il bit

		if (startingBit == 0)
		{
			startingBit = 1;
		}
		else
		{
			startingBit = 0;
		}
		for (auto element : chosenNodes)
		{
			transformationCoding(2, root, element->data);	//Level-Swap
			reCalcFreq(root);
		}
	}

	getCodes(root, "");
	cout << "Simboli dopo le trasformazioni: " << endl;
	for (auto element : codes)
	{
		cout << element.first << " , frequenza : " << element.second << endl;
	}
}

void Huffman::runBulkTransformations(Node* root, string key) {

	/*Riceve la chiave originale, e la converte in una corretta.
	Fatto questo, prende i nodi interni e seleziona solo quelli abbinati ad 1 nella chiave. Applica la trasformazione (quella scelta è levelSwap) ad essi.
	*/

	int k = 1;
	string sKey = getConvertedKey(key, &k); //Necessario passare valore 1 per k, siccome la funzione è universale.
	vector<Node*> chosenNodes;
	addHuffmanTreeLeaves(root, &chosenNodes);	//Aggiunge tutte le foglie, successivamente cancella quelle corrispondenti a bit 0 nella chiave.

	int c = 0;
	for (char ch : sKey)
	{
		if (ch == '0')	//Cancella il nodo scelto
		{
			chosenNodes.erase(chosenNodes.begin() + c);
		}
		else c++;
	}

	for (auto element : chosenNodes)
	{
			transformationCoding(2, root, element->data);	//Level-Swap
			reCalcFreq(root);
	}
	getCodes(root, "");
	cout << "Simboli dopo le trasformazioni: " << endl;
	for (auto element : codes)
	{
		cout << element.first << " , frequenza : " << element.second << endl;
	}
}

void Huffman::huffmanEncode(string filename, string extension, int transformationMethod, int numDC) {

	ifstream inputFile(filename + extension);
	ofstream DCFile(filename + " secure" + extension);

	string inputString, encodedString;

	std::stringstream buf;
	buf << inputFile.rdbuf();
	inputString = buf.str();
	inputFile.close();

	//Parte pseudocasuale di inserimento dei caratteri di DC
	srand(time(NULL)); //Genera un nuovo seed per il motore probabilistico

	/*Metodo sicuro contro CPA*/

	int currOutput = 0;	//Numero di caratteri trasformati finora
	int currPos = 0;	//Posizione del carattere da trasformare
	int numOutput = numDC;

	while (currOutput < numOutput)
	{
		int range = (inputString.length() - 1) - currPos + 1;
		cout << range << endl;
		currPos = rand() % range + currPos;
		char previousvalue = inputString[currPos];
		float chance = (float)rand() / RAND_MAX;
		if (int(previousvalue) >= 0) //Non è un carattere già modificato
		{
			//cout << "Codifico un carattere: " << currOutput << endl;
			char newvalue = (char) int(previousvalue) - int(0x7f);
			inputString[currPos] = newvalue;
			currOutput++;
		}
		if (currPos == inputString.length() - 1)	//Se finisce di attraversare la stringa, riparte dall'inizio.
		{
			currPos = 0;
		}
	}

	//Scrive in secure
	DCFile << inputString;
	DCFile.close();

	calcFreq(inputString);

	buildHuffmanTree(inputString.length());

	getCodes(HuffmanTree.top(), "");

	cout << "Simboli prima delle trasformazioni: " << endl;
	for (auto element : codes)
	{
		cout << element.first << " , frequenza : " << element.second << endl;
	}

	//Imposta metodo di scelta trasformazioni
	switch (transformationMethod)
	{
	case 1:
		runBulkTransformations(HuffmanTree.top(), key);
		break;
	case 2:
		runKTransformations(HuffmanTree.top(), key, frequencies.size() - 1);
		break;
	}

	getCodes(HuffmanTree.top(), "");

	for (auto i : inputString)
	{
		encodedString += codes[i];
	}


	//Salva su file binario la codifica

	string name = filename + ".bin";
	writeToBin(name, encodedString);



	storeSecureHuffmanTree(HuffmanTree.top(), filename, key);
	//DEBUG: Serve per i test.

	ofstream debugEncodingFile(filename + " encoded" + extension);
	debugEncodingFile << encodedString;
	debugEncodingFile.close();

	ofstream debugTreeFile(filename + " tree" + extension);
	string tree = "";
	saveHuffmanTree(HuffmanTree.top(), tree);
	debugTreeFile << tree;
	debugTreeFile.close();

	cout << "Terminata codifica" << endl;
}

void Huffman::huffmanDecode(string filename, string key) {
	ofstream fdecoding(filename + " decoded.txt");

	string name = filename + ".bin";

	string binString = readFromBin(name);

	//Necessario decodificare anche l'albero di decodifica.

	name = filename + " tree.bin";

	string decodedTree = readFromBin(name);

	decodedTree = applyOneTimePad(decodedTree, key);

	//Ricostruisce il formato originale dell'albero, convertendo i simboli in formato binario in caratteri di nuovo.

	string ch = "";	//Stringa buffer
	int i = 0;

	while (i < decodedTree.size())
	{
		if (decodedTree[i] == '1') // Trovato marker che indica che il byte successivo è un simbolo
		{
			for (int j = i + 1; j < i + 9; j++)
			{
				ch = ch + decodedTree[j];	//Aggiunge i bit del carattere alla stringa buffer ch
			}

			int decodedASCII = stoi(ch, nullptr, 2);
			char decodedValue = static_cast<char>(decodedASCII);

			if (isdigit(decodedValue) && ((decodedValue - '0') % 10 == 1))	//Gestisce caso eccezionale per cui 1 è un simbolo da codificare, e quindi andrebbe in confusione
			{
				decodedTree.erase(i + 2, 7);	//Cancella i bit del numero
				i++;	//Passa alla posizione successiva al marker
				decodedTree[i] = decodedValue;	//Aggiunge il numero alla stringa di decodifica
			}
			else
			{
				decodedTree.erase(i + 1, 7);	//Cancella i bit del carattere
				decodedTree[i + 1] = decodedValue;	//Aggiunge il carattere alla stringa di decodifica
			}
			ch = "";	//Reset della stringa contenente i caratteri, in modo da considerare il prossimo
		}
		i++;
	}

	//Adesso si può ricostruire l'albero a partire dalla codifica.

	Node* root = rebuildHuffmanTree(decodedTree);

	cout << "Terminato il rebuild" << endl;

	//Non è necessaria decodifica delle trasformazioni.	Si può direttamente decodificare la stringa.

	string decodedString = decodeString(root, binString);

	fdecoding << decodedString;

	fdecoding.close();
	cout << "Terminata decodifica";
}


