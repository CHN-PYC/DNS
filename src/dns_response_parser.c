#include "dns.h"
#include "cache.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
int parse_dns_response_for_cache(const uint8_t* response, size_t response_len, 
                                uint32_t* ip_out, uint32_t* ttl_out) {
    // 检查基础长度
    if (response_len < sizeof(dns_header_t) )return 0;

    dns_header_t *header = (dns_header_t*)response;
    uint16_t ancount = ntohs(header->ancount);
    if (ancount == 0) return 0;

    // 跳过问题部分
    size_t pos = sizeof(dns_header_t);
    while (pos < response_len && response[pos] != 0) {
        pos += 1 + response[pos]; // 跳过标签
    }
    pos += 5; // 跳过null结束符+QTYPE/QCLASS

    // 遍历回答记录
    for (int i = 0; i < ancount && pos + 12 <= response_len; i++) {
        // 检查是否是A记录
        uint16_t type = ntohs(*(uint16_t*)(response + pos + 2));
        if (type == 1) { // A记录
            *ttl_out = ntohl(*(uint32_t*)(response + pos + 6));
            uint16_t rdlen = ntohs(*(uint16_t*)(response + pos + 10));
            
            if (rdlen == 4 && pos + 12 + 4 <= response_len) {
                *ip_out = *(uint32_t*)(response + pos + 12);
                return 1;
            }
        }
        // 移动到下一条记录
        pos += 12 + ntohs(*(uint16_t*)(response + pos + 10));
    }
    return 0;
}