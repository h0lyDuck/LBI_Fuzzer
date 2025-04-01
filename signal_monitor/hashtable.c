#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hashtable.h"

/**
 * 哈希函数，用于计算给定键的哈希值
 * 
 * @param key 要计算哈希值的键
 * @return 计算得到的哈希值
 */
unsigned int hash_function(unsigned long long int key)
{
    // 使用取模运算计算哈希值，确保哈希值在哈希表的大小范围内
    return key % TABLE_SIZE;
}

/**
 * 在哈希表中插入一个键值对，其中值为无符号长整型
 * 
 * @param hashTable 指向哈希表的指针
 * @param key 要插入的键
 * @param value 要插入的无符号长整型值
 * @return 无返回值
 */
void hashtable_insert_number(HashTable *hashTable, unsigned long long int key, unsigned long long int value)
{
    // 使用哈希函数计算键的索引
    unsigned int index = hash_function(key);
    // 为新的键值对分配内存
    KeyValuePair *newPair = (KeyValuePair *)malloc(sizeof(KeyValuePair));
    // 设置新键值对的键
    newPair->key = key;
    // 设置新键值对的值
    newPair->value = value;
    // 设置新键值对的下一个指针为NULL
    newPair->next = NULL;

    // 如果哈希表中该索引位置为空
    if (hashTable->table[index] == NULL)
    {
        // 将新键值对插入到该索引位置
        hashTable->table[index] = newPair;
    }
    else
    {
        // 获取该索引位置的链表头指针
        KeyValuePair *current = hashTable->table[index];
        // 遍历链表，找到最后一个节点
        while (current->next != NULL)
        {
            current = current->next;
        }
        // 将新键值对插入到链表的末尾
        current->next = newPair;
    }
}

/**
 * 在哈希表中插入一个键值对，其中值为字符串类型
 * 
 * @param hashTable 指向哈希表的指针
 * @param key 要插入的键
 * @param s_value 要插入的字符串值
 * @return 无返回值
 */
void hashtable_insert_string(HashTable *hashTable, unsigned long long int key, char *s_value)
{
    // 使用哈希函数计算键的索引
    unsigned int index = hash_function(key);
    // 为新的键值对分配内存
    KeyValuePair *newPair = (KeyValuePair *)malloc(sizeof(KeyValuePair));
    // 设置新键值对的键
    newPair->key = key;
    // 复制字符串值到新键值对中
    newPair->s_value = strdup(s_value);
    // 设置新键值对的下一个指针为NULL
    newPair->next = NULL;

    // 如果哈希表中该索引位置为空
    if (hashTable->table[index] == NULL)
    {
        // 将新键值对插入到该索引位置
        hashTable->table[index] = newPair;
    }
    else
    {
        // 获取该索引位置的链表头指针
        KeyValuePair *current = hashTable->table[index];
        // 遍历链表，找到最后一个节点
        while (current->next != NULL)
        {
            current = current->next;
        }
        // 将新键值对插入到链表的末尾
        current->next = newPair;
    }
}

/**
 * 在哈希表中搜索指定键的值
 * 
 * @param hashTable 指向哈希表的指针
 * @param key 要搜索的键
 * @param mode 搜索模式，可以是SEARCH_NUMBER或SEARCH_STRING
 * @param result 用于存储搜索结果的指针
 * @return 如果找到键，则返回1；否则返回0
 */
int hashtable_search(HashTable *hashTable, unsigned long long int key, int mode, void *result)
{
    // 使用哈希函数计算键的索引
    unsigned int index = hash_function(key);
    // 获取哈希表中该索引位置的链表头指针
    KeyValuePair *current = hashTable->table[index];
    // 遍历链表，查找键为key的节点
    while (current != NULL)
    {
        // 如果找到键为key的节点
        if (current->key == key)
        {
            // 根据搜索模式处理结果
            if (mode == SEARCH_NUMBER)
            {
                // 将结果指针转换为unsigned long long int类型的指针，并赋值为当前节点的value
                *(unsigned long long int *)result = current->value;
            }
            else if (mode == SEARCH_STRING)
            {
                // 将结果指针转换为char**类型的指针，并赋值为当前节点的s_value的副本
                *(char **)result = strdup(current->s_value);
            }
            // 返回1表示找到
            return 1;
        }
        // 更新current指针为下一个节点
        current = current->next;
    }
    // 返回0表示未找到
    return 0; 
}

/**
 * 从哈希表中删除指定键的键值对
 * 
 * @param hashTable 指向哈希表的指针
 * @param key 要删除的键
 * @return 无返回值
 */
void hashtable_delete(HashTable *hashTable, unsigned long long int key)
{
    // 使用哈希函数计算键的索引
    unsigned int index = hash_function(key);
    // 获取哈希表中该索引位置的链表头指针
    KeyValuePair *current = hashTable->table[index];
    // 用于记录当前节点的前一个节点
    KeyValuePair *prev = NULL;

    // 遍历链表，查找键为key的节点
    while (current != NULL)
    {
        // 如果找到键为key的节点
        if (current->key == key)
        {
            // 如果该节点是链表的头节点
            if (prev == NULL)
            {
                // 将链表头指针指向下一个节点
                hashTable->table[index] = current->next;
            }
            else
            {
                // 将前一个节点的next指针指向当前节点的下一个节点
                prev->next = current->next;
            }
            // 如果当前节点有字符串值，释放其内存
            if (current->s_value)
            {
                free(current->s_value);
            }
            // 释放当前节点的内存
            free(current);
            // 删除操作完成，返回
            return;
        }
        // 更新prev指针为当前节点
        prev = current;
        // 更新current指针为下一个节点
        current = current->next;
    }
}

// int main()
// {
//     HashTable hashTable;
//     unsigned long long int value, res;
//     char *a;
//     for (int i = 0; i < TABLE_SIZE; i++)
//     {
//         hashTable.table[i] = NULL;
//     }
//     hashtable_insert_number(&hashTable, 0xff000001 - 100, 0x15b8);
//     hashtable_insert_number(&hashTable, 0xff000001, 0x15b8);
//     hashtable_insert_number(&hashTable, 0xff000001 + 100, 0x15b9);
//     hashtable_insert_number(&hashTable, 2, 20);
//     hashtable_insert_string(&hashTable, 0xff000001 + 200, "hahaha");

//     res = hashtable_search(&hashTable, 0xff000001 + 200, 2, &a);
//     if (res == 1)
//     {
//         puts(a);
//     }
//     res = hashtable_search(&hashTable, 0xff000001, 1, &value);
//     if (res == 1)
//     {
//         printf("找到键为0xff000001的值：%d\n", value);
//     }

//     hashtable_delete(&hashTable, 0xff000001);
//     res = hashtable_search(&hashTable, 0xff000001, 1, &value);
//     if (res == 0)
//     {
//         printf("键为0xff000001的元素已删除\n");
//     }

//     res = hashtable_search(&hashTable, 0xff000001 + 100, 1, &value);
//     if (res == 1)
//     {
//         printf("找到键为0xff000001+100的值：%d\n", value);
//     }
//     return 0;
// }