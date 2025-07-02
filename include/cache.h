#ifndef CACHE_H
#define CACHE_H

#include <stdint.h>
#include <time.h>

#define CACHE_SIZE 128
#define MAX_TTL 86400

typedef struct {
    char domain[256];
    uint32_t ip;
    time_t expire_time;
    time_t last_access;
    int valid;
} cache_entry_t;

void init_cache();
int find_in_cache(const char* domain, uint32_t* ip_out);
void insert_into_cache(const char* domain, uint32_t ip, uint32_t ttl);
void dump_cache();  // 移除参数
void cleanup_expired_entries();

#endif // CACHE_H
