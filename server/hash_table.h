/*
 * hash_table.h
 *
 *  Created on: Dec 10, 2015
 *      Author: dbailey
 *         Org: Waverley Labs, LLC
 *
 */

#ifndef HASH_TABLE_H_
#define HASH_TABLE_H_

//#define NDEBUG

#include <stdio.h>
#include <inttypes.h>

#include <stdlib.h>
#include <string.h>

#define DEFAULT_NUMBER_OF_BUCKETS 100
#define MAX_NUMBER_OF_BUCKETS 100000

typedef int (*hash_table_compare)(void *a, void *b);
typedef uint32_t (*hash_table_hash_func)(void *key);

typedef struct hash_table_node {
    void *key;
    void *data;
    uint32_t hash;
    struct hash_table_node *next;
} hash_table_node_t;

typedef void (*hash_table_delete_cb)(hash_table_node_t *node);

typedef struct hash_table {
	hash_table_node_t **buckets;
    uint32_t length;
    hash_table_compare compare;
    hash_table_hash_func hash_func;
    hash_table_delete_cb delete_cb;
} hash_table_t;


typedef int (*hash_table_traverse_cb)(hash_table_node_t *node, void *cb_arg);

hash_table_t *hash_table_create(const uint32_t length, hash_table_compare compare, hash_table_hash_func hash_func, hash_table_delete_cb delete_cb);
void hash_table_destroy(hash_table_t *tbl);

int hash_table_set(hash_table_t *tbl, void *key, void *data);
void *hash_table_get(hash_table_t *tbl, void *key);

int hash_table_traverse(hash_table_t *tbl, hash_table_traverse_cb traverse_cb, void *cb_arg);

int hash_table_delete(hash_table_t *tbl, void *key);

#endif /* HASH_TABLE_H_ */
