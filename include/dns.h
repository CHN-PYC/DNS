#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define MAX_DOMAIN_LEN 256
#define MAX_ENTRIES 1024
#define DNS_TYPE_A 1
#define DNS_CLASS_IN 1
#define DNS_QR_RESPONSE 0x8000
#define DNS_RCODE_NXDOMAIN 3
#define DNS_FLAG_RD     0x0100
#define DNS_FLAG_RA     0x0080
// DNS Header structure
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

// DNS Question section
typedef struct {
    char *qname;
    uint16_t qtype;
    uint16_t qclass;
} dns_question_t;

typedef struct {
    char domain[MAX_DOMAIN_LEN];
    uint32_t ip;
    time_t cached_time; // 记录缓存时间
    int is_cached; // 是否是缓存的条目
} dns_entry_t;


// DNS Parser
int parse_dns_query(const uint8_t* buffer, size_t len, dns_header_t* header, dns_question_t* question);
char* parse_domain_name(const uint8_t* buffer, size_t* pos);
void append_domain_name(const char* name, uint8_t* buf, size_t* pos);
// DNS Builder
void build_a_response(const dns_header_t* req_header, const char* domain, uint32_t ip, uint8_t* resp_buffer, size_t* resp_len);
void build_error_response(const dns_header_t* req_header, const char* qname, uint8_t* buffer, size_t* resp_len, uint8_t rcode);
void build_nxdomain_response(const dns_header_t* req_header, 
                              const uint8_t* query, size_t query_len,
                              uint8_t* resp_buffer, size_t* resp_len);

// DNS utils
void load_dns_table(const char* filename);
int find_local_ip(const char* qname, uint32_t* ip_out);
int forward_query_to_dns_server(const uint8_t* query_buf, size_t query_len, uint8_t* resp_buf, size_t* resp_len);
void insert_cached_entry(const char* domain, uint32_t ip);
void parse_and_cache_answers(const uint8_t* response, size_t resp_len, const char* qname);
void handle_forwarded_response(const uint8_t *response, size_t response_len, const dns_question_t question);
void load_dns_table(const char* filename);

//
int parse_dns_response_for_cache(const uint8_t* response, size_t len, 
                               uint32_t* ip_out, uint32_t* ttl_out);
#endif // DNS_H