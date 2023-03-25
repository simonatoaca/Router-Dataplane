#ifndef TRIE_H
#define TRIE_H

typedef struct trie_node_t trie_node_t;
struct trie_node_t {
	/* Value associated with key (set if end_of_word = 1) */
	void* value;

	/* 1 if current node marks the end of a word, 0 otherwise */
	int end_of_word;

	trie_node_t** children;
	int n_children;
};

typedef struct trie_t trie_t;
struct trie_t {
	trie_node_t* root;
	
	/* Number of keys */
	int size;

	/* Generic Data Structure */
	int data_size;

	/* Trie-Specific, alphabet properties */
	int alphabet_size;
	char* alphabet;

	/* Callback to free value associated with key, should be called when freeing */
	void (*free_value_cb)(void*);

	/* Optional - number of nodes, useful to test correctness */
	int nNodes;
};

trie_t* trie_create(int data_size, int alphabet_size, char* alphabet, void (*free_value_cb)(void*));

void trie_insert(trie_t* trie, char* key, void* value);

/* Returns value associated with key if it exists, NULL otherwise */
void* trie_search(trie_t* trie, char* key);

/* Returs 1 if key exists and was succesfully deleted, 0 otherwise */
int trie_remove(trie_t* trie, char* key);

void trie_free(trie_t** trie);

#endif