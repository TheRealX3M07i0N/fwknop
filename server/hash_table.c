/*
 * hash_table.c
 *
 *  Created on: Dec 10, 2015
 *      Author: dbailey
 *         Org: Waverley Labs, LLC
 *
 */

#include "hash_table.h"
#include "bstrlib.h"
#include "dbg.h"

/*
 * Func: default_compare
 * Args: void *a, void *b
 * Expl: This is the default method for comparing two table keys. It casts both keys to bstrings
 *          as defined in the bstrlib library and runs a comparison. It returns 0 if the strings
 *          are identical. Otherwise, a positive or negative value may be returned depending on
 *          the differences between the strings.
 */
static int default_compare(void *a, void *b)
{
    return bstrcmp((bstring)a, (bstring)b);
}

/**
 * Func: default_hash
 * Args: void *a - the key to be hashed
 * Expl: This is the default hash method used by this hash table. This is the simple Bob
 *       Jenkins's hash algorithm taken from the wikipedia description. It will cast the
 *       key argument to a bstring and then generate the hash value of that key.
 */
static uint32_t default_hash(void *a)
{
    size_t len = blength((bstring)a);
    char *key = bdata((bstring)a);
    uint32_t hash = 0;
    uint32_t i = 0;

    if(key == NULL)
        return -1;

    for(hash = i = 0; i < len; ++i)
    {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);

    return hash;
}


/**
 * Func: hash_table_create
 * Args: const uint32_t length - Number of buckets in the hash table. Accepts any value
 *              between 0 and MAX_NUMBER_OF_BUCKETS, inclusive. 0 results in a length of
 *              DEFAULT_NUMBER_OF_BUCKETS.
 *
 *       hash_table_compare compare - Pointer to a function for comparing two keys. Accepts
 *           NULL, resulting in selecting the default compare function.
 *
 *       hash_table_hash_func hash_func - Pointer to a function for hashing a key. Accepts
 *           NULL, resulting in selecting the default hashing function.
 *
 *       hash_table_delete_cb delete_cb - Pointer to a function to call for each populated
 *           node during hash_table_destroy in order to deallocate all memory. This can be NULL.
 *
 * Expl: Function for creating hash table. It's important to note that this implementation
 *       allows for keys and data of any type.
 */
hash_table_t *hash_table_create(const uint32_t length, hash_table_compare compare, hash_table_hash_func hash_func, hash_table_delete_cb delete_cb)
{
    hash_table_t *tbl = NULL;
    uint32_t i;

    // Check that the desired table length is valid
    check( ((length >= 0) && (length < MAX_NUMBER_OF_BUCKETS)), "Table length must be between 0 and %i, inclusive.", MAX_NUMBER_OF_BUCKETS);

    // Ensure the user provided a delete callback
    check((delete_cb != NULL), "A function for deleting keys and data must be provided.");

    // If the user chose length 0, use DEFAULT_NUMBER_OF_BUCKETS
    // Otherwise, use their desired value
    uint32_t final_length = length == 0 ? DEFAULT_NUMBER_OF_BUCKETS : length;

    // Allocate memory for the table and verify the allocation was successful
    tbl = calloc(1, sizeof(hash_table_t));
    check_mem(tbl);

    // Allocate memory for the array of pointers to buckets, i.e. first node in each bucket
    tbl->buckets = calloc(final_length, sizeof(hash_table_node_t *));
    check_mem(tbl->buckets);

    tbl->length = final_length;
    tbl->compare = compare == NULL ? default_compare : compare;
    tbl->hash_func = hash_func == NULL ? default_hash : hash_func;
    tbl->delete_cb = delete_cb;

    debug("Initializing buckets entries to NULL.");
    for (i = 0; i < final_length; i++)
        tbl->buckets[i] = NULL;

    debug("Done.");
    return tbl;

error:
    if(tbl)
    {
        hash_table_destroy(tbl);
    }

    return NULL;
}


/**
 * Func: hash_table_destroy
 * Args: hash_table_t *tbl - Pointer to the table being destroyed.
 * Expl: Function for deleting a hash table.
 */
void hash_table_destroy(hash_table_t *tbl)
{
    int i = 0;

    // if the table exists
    if(tbl) {
        // if the array of buckets exists
        if(tbl->buckets)
        {
            debug("HASH_TABLE_DESTROY: buckets is not null.");
            debug("HASH_TABLE_DESTROY: table length: %" PRIu32 ".", tbl->length);

            // step through the array of buckets
            for(i = 0; i < tbl->length; i++)
            {
                hash_table_node_t *node = tbl->buckets[i];

                if(node != NULL) debug("HASH_TABLE_DESTROY: bucket %d was initialized.", i);

                // if a bucket is not null, walk through the linked list
                // deleting all nodes
                while(node != NULL)
                {
                    debug("HASH_TABLE_DESTROY: KEY: %s", bdata((bstring)node->key));
                    if(node->next != NULL)
                        debug("HASH_TABLE_DESTROY: Next node is not null.");
                    else
                        debug("HASH_TABLE_DESTROY: Next node is null.");

                    // hold the next node in the list
                    hash_table_node_t *next = node->next;

                    // if a callback was provided for deleting data, run it
                    if(tbl->delete_cb) tbl->delete_cb(node);

                    // free the node itself
                    free(node);
                    debug("HASH_TABLE_DESTROY: Node structures freed.");

                    // move to the next node in this bucket
                    node = next;
                }
            }

            debug("HASH_TABLE_DESTROY: Done deleting nodes.");

            // free the buckets array
            free(tbl->buckets);
        }

        debug("HASH_TABLE_DESTROY: Freeing the table itself.");

        // free the table structure
        free(tbl);
    }
    debug("HASH_TABLE_DESTROY: Exiting function.");
}

/**
 * Func: hash_table_node_create
 * Args: const uint32_t hash - calculated hash value based on the key.
 *
 *       void *key - pointer to the key.
 *
 *       void *data - pointer to the data.
 *
 * Expl: Non-public function for creating a hash table node. It's important to note that this
 *       implementation allows for keys and data of any type. Returns a pointer to the node or
 *       NULL on failure
 */
static inline hash_table_node_t *hash_table_node_create(const uint32_t hash, void *key, void *data)
{
    hash_table_node_t *node = calloc(1, sizeof(hash_table_node_t));
    check_mem(node);

    node->key = key;
    node->data = data;
    node->hash = hash;
    node->next = NULL;

    return node;

error:
    return NULL;
}

/*
static inline hash_table_node_t *hash_table_bucket_get(hash_table_t *tbl, void *key,
        int create, uint32_t *hash_out)
{
    check((tbl->length), "Invalid table length: %" PRIu32 " ", (tbl->length));

    debug("Returned from table length check.");

    uint32_t hash = tbl->hash_func(key);
    debug("Got hash.");

    int bucket_n = hash % (tbl->length);
    debug("Bucket number: %d", bucket_n);

    check(bucket_n >= 0, "Invalid bucket found: %d", bucket_n);
    *hash_out = hash; // store it for the return so the caller can use it

    hash_table_node_t *bucket = tbl->buckets[bucket_n];
    debug("Set bucket.");

    if(!bucket && create)
    {
        debug("Entered bucket create clause.");
        // new bucket, set it up
        bucket = hash_table_node_create(hash, key, NULL);
        check_mem(bucket);
        tbl->buckets[bucket_n] = bucket;
    }

    debug("Returning a bucket.");
    return bucket;

error:
    return NULL;
}
*/

/**
 * Func: hash_table_node_get
 * Args: hash_table_t *tbl - pointer to the hash table.
 *
 *       void *key - pointer to the key.
 *
 *       uint32_t *hash - sets/returns the calculated hash value.
 *
 *       int *bucket_num - set/returns the calculated bucket number.
 *
 *       hash_table_node_t **prev - this is set to null if the desired node is the first
 *           in the bucket.
 *
 * Expl: Non-public function for finding a hash table node.
 */
static inline hash_table_node_t * hash_table_node_get(hash_table_t *tbl, void *key,
        uint32_t *hash, int *bucket_num, hash_table_node_t **prev)
{
    int i = 0;
    *prev = NULL;

    // ensure the table's length is nonzero
    check((tbl->length) > 0, "Invalid table length: %" PRIu32 " ", (tbl->length));

    debug("Returned from table length check.");

    // calculate the hash value from the key
    if((*hash = tbl->hash_func(key)) < 0)
        goto error;
    debug("Got hash.");

    // get the bucket number from the hash value
    *bucket_num = *hash % (tbl->length);
    debug("Bucket number: %d", *bucket_num);

    // ensure we got a logical bucket number
    check(*bucket_num >= 0, "Invalid bucket number found: %d", *bucket_num);

    // retrieve the first node in the bucket
    hash_table_node_t *node = tbl->buckets[*bucket_num];
    debug("Set node.");

    // if there is a first node, begin walking the list
    while(node != NULL)
    {
        debug("TRY: %d", i);
        // make sure the hash and the key both match what's in the node
        if(node->hash == *hash && tbl->compare(node->key, key) == 0)
        {
            // found a match so return it
            debug("Entered if clause.");
            return node;
        }

        debug("Skipped if clause.");
        i++;

        // keep track of the previous node
        *prev = node;

        // step to the next node in the list
        debug("Assigning 'node'");
        node = node->next;
        debug("Finished assignments.");
    }

    // return the node
    // if a match was not found this should return NULL
    return node;

error:
    return NULL;


}

/**
 * Func: hash_table_set
 * Args: hash_table_t *tbl - pointer to the hash table.
 *
 *       void *key - pointer to the key.
 *
 *       void *data - pointer to the data.
 *
 * Expl: Function for setting a hash table node. If a node with the same key
 *          is found, it is completely destroyed and replaced by an entirely new node,
 *          including making sure the old key and data memory are freed.
 */
int hash_table_set(hash_table_t *tbl, void *key, void *data)
{
    uint32_t hash = 0;
    int bucket_num = 0;
    hash_table_node_t *old_node = NULL;
    hash_table_node_t *prev_node = NULL;
    hash_table_node_t *new_node = NULL;

    debug("Entered hash_table_set.");

    // look for the old node first
    // even if it doesn't exist, we want the hash value back
    old_node = hash_table_node_get(tbl, key, &hash, &bucket_num, &prev_node);

    // create the new node
    new_node = hash_table_node_create(hash, key, data);
    check_mem(new_node);

    // if prev_node was set, this node takes the old one's place in the list
    if(prev_node)
    {
        (prev_node)->next = new_node;
    }
    else
    {
        // this is the first node in the bucket
        tbl->buckets[bucket_num] = new_node;
    }

    // if we did find a node with this key
    if(old_node)
    {
        // grab the pointer to the next node in the list
        new_node->next = old_node->next;

        // destroy the old node
        tbl->delete_cb(old_node);
        free(old_node);
    }

    return 0;

error:
    return -1;
}

/**
 * Func: hash_table_get
 * Args: hash_table_t *tbl - pointer to the hash table.
 *
 *       void *key - pointer to the key.
 *
 * Expl: Function for finding a hash table node. This returns a pointer to
 *       the node's data.
 */
void *hash_table_get(hash_table_t *tbl, void *key)
{
    uint32_t hash = 0;
    int bucket_num = 0;
    hash_table_node_t *prev_node = NULL;

    hash_table_node_t *node = hash_table_node_get(tbl, key, &hash, &bucket_num, &prev_node);
    if(!node) return NULL;

    debug("Found desired node.");
    return node->data;
}


/**
 * Func: hash_table_traverse
 * Args: hash_table_t *tbl - pointer to the hash table.
 *
 *       hash_table_traverse_cb traverse_cb - pointer to a function to call for each
 *           populated node that's found.
 *
 * Expl: Function for traversing the hash table and calling the callback function
 *          for each populated node that's found. This returns 0 or prints an error
 *          and returns the value returned by the callback function.
 */
int hash_table_traverse(hash_table_t *tbl, hash_table_traverse_cb traverse_cb, void *cb_arg)
{
    int i = 0;
    int rc = 0;
    hash_table_node_t *node = NULL;
    hash_table_node_t *next = NULL;

    for(i = 0; i < (tbl->length); i++) {
        node = tbl->buckets[i];
        while(node)
        {
            // in case the callback is deleting nodes
            next = node->next;
            rc = traverse_cb(node, cb_arg);
            if(rc != 0) return rc;
            node = next;
        }
    }

    return 0;
}

/**
 * Func: hash_table_delete
 * Args: hash_table_t *tbl - pointer to the hash table.
 *
 *       void *key - pointer to the key.
 *
 * Expl: Function for deleting a hash table node. This calls the previously
 *       registered callback function for deleting the key and data stored
 *       in the node and then destroys the node itself.
 */
int hash_table_delete(hash_table_t *tbl, void *key)
{
    uint32_t hash = 0;
    int bucket_num = 0;
    hash_table_node_t *prev = NULL;

    debug("HASH_TABLE_DELETE: entered.");

    hash_table_node_t *node = hash_table_node_get(tbl, key, &hash, &bucket_num, &prev);
    if(!node) return -1;

    debug("HASH_TABLE_DELETE: Found node.");

    if(prev == NULL)
    {
        // node was the first in this bucket
        debug("HASH_TABLE_DELETE: Node was first in bucket.");
        tbl->buckets[bucket_num] = node->next;
    }
    else
    {
        // node was anything other than first in this slot
        debug("HASH_TABLE_DELETE: Node was not first in bucket.");
        prev->next = node->next;
    }

    debug("HASH_TABLE_DELETE: Free memory.");

    tbl->delete_cb(node);
    free(node);

    return 0;
}

