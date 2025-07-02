#include "dns.h"
#include <string.h>

int parse_dns_query(const uint8_t* buffer, size_t len, dns_header_t* header, dns_question_t* question) {
    if (len < sizeof(dns_header_t)) return -1;

    memcpy(header, buffer, sizeof(dns_header_t));
    header->id = ntohs(header->id);
    header->flags = ntohs(header->flags);
    header->qdcount = ntohs(header->qdcount);
    header->ancount = ntohs(header->ancount);
    header->nscount = ntohs(header->nscount);
    header->arcount = ntohs(header->arcount);

    if ((header->flags & DNS_QR_RESPONSE) != 0) return -2;

    size_t pos = sizeof(dns_header_t);
    question->qname = parse_domain_name(buffer, &pos);
    question->qtype = ntohs(*(uint16_t*)(buffer + pos)); pos += 2;
    question->qclass = ntohs(*(uint16_t*)(buffer + pos));
    return 0;
}

char* parse_domain_name(const uint8_t* buffer, size_t* pos) {
    char name[MAX_DOMAIN_LEN];
    int i = 0;
    while (buffer[*pos] != 0) {
        uint8_t len = buffer[(*pos)++];
        memcpy(name + i, buffer + *pos, len);
        i += len;
        name[i++] = '.';
        *pos += len;
    }
    (*pos)++;
    name[i - 1] = '\0';
    return strdup(name);
}

void append_domain_name(const char* name, uint8_t* buf, size_t* pos) {
    const char* start = name;
    const char* end;
    while ((end = strchr(start, '.')) != NULL) {
        size_t len = end - start;
        buf[(*pos)++] = len;
        memcpy(buf + *pos, start, len);
        *pos += len;
        start = end + 1;
    }
    size_t len = strlen(start);
    buf[(*pos)++] = len;
    memcpy(buf + *pos, start, len);
    *pos += len;
    buf[(*pos)++] = 0;
}