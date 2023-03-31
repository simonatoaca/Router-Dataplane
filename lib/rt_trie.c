#include "rt_trie.h"
#include "lib.h"

trie_node_t *trie_create_node(rt_trie_t *trie) {
	trie_node_t *node = malloc(sizeof(*node));

	DIE(!node, "Failed node alloc!\n");

	node->value = calloc(1, trie->data_size);
	node->children = calloc(trie->bit_values, sizeof(trie_node_t *));

	DIE(!node->children, "Failed tree children alloc\n");

	node->end_of_word = 0;
	node->n_children = 0;
	return node;
}

rt_trie_t *trie_create(int data_size) {
	rt_trie_t *trie = malloc(sizeof(*trie));
	DIE(!trie, "Failed trie alloc\n");

	trie->bit_values = BIT_VALUES;
	trie->data_size = data_size;
	trie->size = 0;

	trie->root = trie_create_node(trie);

	DIE(!trie->root, "Failed trie root alloc\n");

	trie->root->value = NULL;
	return trie;
}

static void __trie_insert_helper(rt_trie_t *trie, trie_node_t *node,
								 uint32_t key, uint32_t mask, void *value) {

	if (!mask) {
		if (node->end_of_word) {
			if (((struct route_table_entry *)value)->mask > 
				((struct route_table_entry *)node->value)->mask) {
				memcpy(node->value, value, trie->data_size);		
			}
		} else {
			memcpy(node->value, value, trie->data_size);
			node->end_of_word = 1;
		}
		return;
	}

	trie_node_t *next_node = node->children[GET_FIRST_BIT(key)];
	if (!next_node) {
		node->children[GET_FIRST_BIT(key)] = trie_create_node(trie);
		node->n_children++;
	}

	__trie_insert_helper(trie, node->children[GET_FIRST_BIT(key)], key << 1, mask << 1, value);
}

void trie_insert(rt_trie_t* trie, uint32_t key, uint32_t mask, void* value) {
	DIE(!trie, "Trie does not exist!\n");

	/* Really important conversion */
	key = ntohl(key);
	mask = ntohl(mask);

	__trie_insert_helper(trie, trie->root, key, mask, value);
}

static void *__trie_search_helper(trie_node_t *node, uint32_t key) {

	trie_node_t *next_node = node->children[GET_FIRST_BIT(key)];

	if (!next_node) {
		return node->value;
	}

	return __trie_search_helper(node->children[GET_FIRST_BIT(key)], key << 1);
}

void *trie_search(rt_trie_t* trie, uint32_t key) {
	DIE(!trie, "Trie does not exist!\n");

	/* Important conversion */
	key = ntohl(key);

	return __trie_search_helper(trie->root, key);
}