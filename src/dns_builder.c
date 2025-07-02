#include "dns.h"
#include <string.h>
#include <arpa/inet.h>

void build_a_response(const dns_header_t* req_header, const char* domain, uint32_t ip, uint8_t* resp_buffer, size_t* resp_len) {
    size_t pos = 0;
    uint16_t id = htons(req_header->id);
    uint16_t flags = htons(0x8180);
    uint16_t qdcount = htons(1);
    uint16_t ancount = htons(1);
    uint16_t nscount = 0;
    uint16_t arcount = 0;

    memcpy(resp_buffer + pos, &id, 2); pos += 2;
    memcpy(resp_buffer + pos, &flags, 2); pos += 2;
    memcpy(resp_buffer + pos, &qdcount, 2); pos += 2;
    memcpy(resp_buffer + pos, &ancount, 2); pos += 2;
    memcpy(resp_buffer + pos, &nscount, 2); pos += 2;
    memcpy(resp_buffer + pos, &arcount, 2); pos += 2;

    size_t qname_offset = pos;
    append_domain_name(domain, resp_buffer, &pos);
    uint16_t qtype = htons(1), qclass = htons(1);
    memcpy(resp_buffer + pos, &qtype, 2); pos += 2;
    memcpy(resp_buffer + pos, &qclass, 2); pos += 2;

    resp_buffer[pos++] = 0xC0;
    resp_buffer[pos++] = (uint8_t)qname_offset;
    uint16_t atype = htons(1), aclass = htons(1);
    uint32_t ttl = htonl(60);
    uint16_t rdlen = htons(4);
    uint32_t net_ip = htonl(ip);

    memcpy(resp_buffer + pos, &atype, 2); pos += 2;
    memcpy(resp_buffer + pos, &aclass, 2); pos += 2;
    memcpy(resp_buffer + pos, &ttl, 4); pos += 4;
    memcpy(resp_buffer + pos, &rdlen, 2); pos += 2;
    memcpy(resp_buffer + pos, &net_ip, 4); pos += 4;

    *resp_len = pos;
}

void build_error_response(const dns_header_t* req_header, const char* qname, uint8_t* buffer, size_t* resp_len, uint8_t rcode) {
    size_t pos = 0;
    uint16_t id = htons(req_header->id);
    uint16_t flags = htons(0x8000 | (rcode & 0x0F));
    uint16_t qdcount = htons(1);

    memcpy(buffer + pos, &id, 2); pos += 2;
    memcpy(buffer + pos, &flags, 2); pos += 2;
    memcpy(buffer + pos, &qdcount, 2); pos += 2;
    memset(buffer + pos, 0, 6); pos += 6;

    append_domain_name(qname, buffer, &pos);
    uint16_t qtype = htons(1), qclass = htons(1);
    memcpy(buffer + pos, &qtype, 2); pos += 2;
    memcpy(buffer + pos, &qclass, 2); pos += 2;

    *resp_len = pos;
}


 void build_nxdomain_response(const dns_header_t* req_header, 
                             const uint8_t* query, size_t query_len,
                             uint8_t* resp_buffer, size_t* resp_len) {
    dns_header_t resp_header = *req_header;
    resp_header.flags = htons(DNS_QR_RESPONSE | DNS_FLAG_RD | DNS_FLAG_RA | DNS_RCODE_NXDOMAIN);

    resp_header.qdcount = htons(1);
    resp_header.ancount = 0;
    resp_header.nscount = 0;
    resp_header.arcount = 0;
    
    size_t pos = 0;
    memcpy(resp_buffer, &resp_header, sizeof(dns_header_t));
    pos += sizeof(dns_header_t);
    
    size_t query_section_len = query_len - sizeof(dns_header_t);
    memcpy(resp_buffer + pos, query + sizeof(dns_header_t), query_section_len);
    pos += query_section_len;
    
    *resp_len = pos;
}
