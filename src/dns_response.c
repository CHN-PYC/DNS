#include "dns.h"
#include "cache.h"
#include <arpa/inet.h>

int parse_dns_response_for_cache(const uint8_t* response, size_t len, 
                               uint32_t* ip_out, uint32_t* ttl_out) {
    if (len < sizeof(dns_header_t)) return 0;

    dns_header_t header;
    memcpy(&header, response, sizeof(header));
    header.ancount = ntohs(header.ancount);

    if (header.ancount == 0) return 0;

    // 跳过问题部分
    size_t pos = sizeof(dns_header_t);
    while (pos < len && response[pos] != 0) {
        uint8_t label_len = response[pos++];
        pos += label_len;
    }
    pos += 5; // 跳过null结束符和QTYPE/QCLASS

    // 解析回答部分
    if (pos + 12 > len) return 0; // 确保有足够的数据

    // 检查是否是A记录
    uint16_t type = ntohs(*(uint16_t*)(response + pos + 2));
    if (type != 1) return 0; // 不是A记录

    *ttl_out = ntohl(*(uint32_t*)(response + pos + 6));
    uint16_t rdlen = ntohs(*(uint16_t*)(response + pos + 10));

    if (rdlen != 4 || pos + 12 + 4 > len) return 0;

    *ip_out = *(uint32_t*)(response + pos + 12);
    return 1;
}