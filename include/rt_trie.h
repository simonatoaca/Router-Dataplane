#ifndef RT_TRIE_H
#define RT_TRIE_H

#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <netinet/in.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "lib.h"

#define BIT_VALUES 2
#define GET_FIRST_BIT(ip) \
	((ip & (((uint32_t)1) << 31)) >> 31)

typedef struct trie_node_t trie_node_t;
struct trie_node_t {
	/* Value associated with key (set if end_of_word = 1) */
	void *value;

	/* 1 if current node marks the end of a word, 0 otherwise */
	int end_of_word;

	trie_node_t **children;
	int n_children;
};

typedef struct rt_trie_t rt_trie_t;
struct rt_trie_t {
	trie_node_t* root;
	
	/* Number of keys */
	int size;

	/* Generic Data Structure */
	int data_size;

	/* Ip bit values */
	int bit_values;
};

trie_node_t *trie_create_node(rt_trie_t *trie);
rt_trie_t *trie_create(int data_size);
void trie_insert(rt_trie_t* trie, uint32_t key, uint32_t mask, void* value);
void *trie_search(rt_trie_t* trie, uint32_t key);

#endif