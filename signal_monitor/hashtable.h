#define TABLE_SIZE 100 // 定义哈希表大小，可根据实际需求调整

// 键值对结构
typedef struct KeyValuePair
{
    unsigned long long int key;
    unsigned long long int value;
    char *s_value;
    struct KeyValuePair *next; // 用于解决冲突，指向下一个键值对
} KeyValuePair;

// 哈希表结构
typedef struct HashTable
{
    KeyValuePair *table[TABLE_SIZE];
} HashTable;

enum
{
    SEARCH_NUMBER,
    SEARCH_STRING
};

unsigned int hash_function(unsigned long long int key);
void hashtable_insert_number(HashTable *hashTable, unsigned long long int key, unsigned long long int value);
void hashtable_insert_string(HashTable *hashTable, unsigned long long int key, char *s_value);
int hashtable_search(HashTable *hashTable, unsigned long long int key, int mode, void *result);
void hashtable_delete(HashTable *hashTable, unsigned long long int key);
