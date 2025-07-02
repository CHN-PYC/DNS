#include "cache.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <pthread.h>

static cache_entry_t cache[CACHE_SIZE];
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

// 保持为static，从头文件中移除声明
static void normalize_domain(const char* src, char* dst) {
    strncpy(dst, src, 255);
    dst[255] = '\0';
    size_t len = strlen(dst);
    
    if (len > 0 && dst[len - 1] == '.') {
        dst[len - 1] = '\0';
        len--;
    }
    for (size_t i = 0; i < len; i++) {
        dst[i] = tolower((unsigned char)dst[i]);
    }
}

void init_cache() {
    pthread_mutex_lock(&cache_mutex);
    for (int i = 0; i < CACHE_SIZE; ++i) {
        cache[i].valid = 0;
    }
    pthread_mutex_unlock(&cache_mutex);
}

int find_in_cache(const char* domain, uint32_t* ip_out) {
    char clean_domain[256];
    normalize_domain(domain, clean_domain);

    time_t now = time(NULL);
    int found = 0;
    
    pthread_mutex_lock(&cache_mutex);
    
    for (int i = 0; i < CACHE_SIZE; ++i) {
        if (!cache[i].valid) continue;
        
        if (strcmp(cache[i].domain, clean_domain) == 0) {
            if (now >= cache[i].expire_time) {
                cache[i].valid = 0; // 标记为过期
                break;
            }
            *ip_out = cache[i].ip;
            cache[i].last_access = now; // 更新访问时间
            found = 1;
            break;
        }
    }
    
    pthread_mutex_unlock(&cache_mutex);
    printf("[Cache] %s for %s\n", 
      found ? "HIT" : "MISS", domain);
    return found;
}

void insert_into_cache(const char* domain, uint32_t ip, uint32_t ttl) {
    
    if (ip == 0 || ip == 0xFFFFFFFF || ttl == 0) return;
    if (ttl > MAX_TTL) ttl = MAX_TTL;

    char clean_domain[256];
    normalize_domain(domain, clean_domain);
    time_t now = time(NULL);

    pthread_mutex_lock(&cache_mutex);
    
    // 1. 尝试替换现有记录
    for (int i = 0; i < CACHE_SIZE; ++i) {
        if (cache[i].valid && strcmp(cache[i].domain, clean_domain) == 0) {
            cache[i].ip = ip;
            cache[i].expire_time = now + ttl;
            cache[i].last_access = now;
            pthread_mutex_unlock(&cache_mutex);
            return;
        }
    }
    
    // 2. 寻找空位
    for (int i = 0; i < CACHE_SIZE; ++i) {
        if (!cache[i].valid) {
            strncpy(cache[i].domain, clean_domain, 255);
            cache[i].domain[255] = '\0';
            cache[i].ip = ip;
            cache[i].expire_time = now + ttl;
            cache[i].last_access = now;
            cache[i].valid = 1;
            pthread_mutex_unlock(&cache_mutex);
            return;
        }
    }
    
    // 3. LRU替换
    int lru_index = 0;
    time_t oldest = cache[0].last_access;
    for (int i = 1; i < CACHE_SIZE; ++i) {
        if (cache[i].last_access < oldest) {
            oldest = cache[i].last_access;
            lru_index = i;
        }
    }
    
    strncpy(cache[lru_index].domain, clean_domain, 255);
    cache[lru_index].domain[255] = '\0';
    cache[lru_index].ip = ip;
    cache[lru_index].expire_time = now + ttl;
    cache[lru_index].last_access = now;
    cache[lru_index].valid = 1;
    
    pthread_mutex_unlock(&cache_mutex); 
    struct in_addr addr;
addr.s_addr = ip;
printf("[Cache] INSERT %s -> %s (TTL=%u)\n",
      domain, inet_ntoa(addr), ttl);
}

void dump_cache() {
    pthread_mutex_lock(&cache_mutex);
    
    time_t now = time(NULL);
    printf("Current cache (now: %ld):\n", now);
    
    for (int i = 0; i < CACHE_SIZE; ++i) {
        if (cache[i].valid) {
            struct in_addr addr;
            addr.s_addr = cache[i].ip;
            printf("[%c] %-30s -> %-15s expire in %6ld sec, last access %ld\n",
                  (now >= cache[i].expire_time) ? 'E' : 'V',
                  cache[i].domain, inet_ntoa(addr),
                  cache[i].expire_time - now,
                  cache[i].last_access);
        }
    }
    
    pthread_mutex_unlock(&cache_mutex);
}