/*
	SD 2022 - Trie
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ALPHABET_SIZE 26
#define ALPHABET "abcdefghijklmnopqrstuvwxyz"

typedef struct trie_node_t trie_node_t;
struct trie_node_t {
	/* Value associated with key (set if end_of_word = 1) */
	void *value;

	/* 1 if current node marks the end of a word, 0 otherwise */
	int end_of_word;

	trie_node_t **children;
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

trie_node_t *trie_create_node(trie_t *trie) {
	trie_node_t *node = malloc(sizeof(*node));

	if (!node) {
		fprintf(stderr, "Failed trie node alloc\n");
		return NULL;
	}

	node->value = calloc(1, sizeof(int));
	node->children = calloc(trie->alphabet_size, sizeof(trie_node_t *));

	if (!node->children) {
		free(node);
		fprintf(stderr, "Failed trie node children alloc\n");
		return NULL;
	}

	node->end_of_word = 0;
	node->n_children = 0;
	return node;
}

trie_t *trie_create(int data_size, int alphabet_size, char *alphabet, void (*free_value_cb)(void*)) {
	trie_t *trie = malloc(sizeof(*trie));
	if (!trie) {
		fprintf(stderr, "Failed trie alloc\n");
		return NULL;
	}

	trie->alphabet = alphabet;
	trie->alphabet_size = alphabet_size;
	trie->data_size = data_size;
	trie->free_value_cb = free_value_cb;
	trie->size = 0; // Number of keys
	trie->nNodes = 1;


	trie->root = trie_create_node(trie);

	if (!trie->root) {
		fprintf(stderr, "Failed trie root alloc\n");
		free(trie);
		return NULL;
	}

	int value = -1;
	memcpy(trie->root->value, &value, sizeof(int));
	return trie;
}

void __trie_insert_helper(trie_t *trie, trie_node_t *node, char *key, void *value) {
	
	if (!strlen(key) && !node->end_of_word) {
		memcpy(node->value, value, sizeof(int));
		node->end_of_word = 1;
		return;
	}

	trie_node_t *next_node = node->children[key[0] - 'a'];
	if (!next_node) {
		node->children[key[0] - 'a'] = trie_create_node(trie);
		node->n_children++;
		trie->nNodes++;
	}

	__trie_insert_helper(trie, node->children[key[0] - 'a'], key + 1, value);
}

void trie_insert(trie_t* trie, char* key, void* value) {
	if (!trie) {
		fprintf(stderr, "Trie does not exist!\n");
		return;
	}
	__trie_insert_helper(trie, trie->root, key, value);
}

void *__trie_search_helper(trie_node_t *node, char *key) {
	if (!strcmp(key, "") && node->end_of_word) {
		return node->value;
	}

	trie_node_t *next_node = node->children[key[0] - 'a'];
	if (!next_node) {
		return NULL;
	}

	return __trie_search_helper(node->children[key[0] - 'a'], key + 1);
}

void *trie_search(trie_t* trie, char* key) {
	if (!trie) {
		fprintf(stderr, "Trie does not exist!\n");
		return NULL;
	}

	if (!strcmp(key, "")) {
		return trie->root->value;
	}

	return __trie_search_helper(trie->root, key);

}

int __trie_remove_helper(trie_t *trie, trie_node_t *node, char *key) {
	if (!strlen(key)) {
		if (node->end_of_word) {
			node->end_of_word = 0;

			return (node->n_children == 0);
		}
		return 0;
	}

	trie_node_t *next_node = node->children[key[0] - 'a'];

	if (next_node && __trie_remove_helper(trie, next_node, key + 1)) {
		trie->free_value_cb(node->value);
		node->n_children--;
		trie->nNodes--;

		if (!node->n_children && !node->end_of_word) {
			return 1;
		}
	}

	return 0;
}

void trie_remove(trie_t* trie, char* key) {
	if (!trie) {
		fprintf(stderr, "Trie does not exist!\n");
		return;
	}

	__trie_remove_helper(trie, trie->root, key);
}

void trie_free(trie_t** pTrie) {
	// TODO
}