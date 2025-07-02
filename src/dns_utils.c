#include "dns.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

// Define dns_entry_t if not defined in dns.h



static dns_entry_t dns_table[MAX_ENTRIES];
static int dns_entry_count = 0;
// Load DNS entries from a file
// Format: <IP> <Domain>
void load_dns_table(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Cannot open dnsrelay.txt");
        exit(1);
    }
    char ip_str[32], domain[MAX_DOMAIN_LEN];
    while (fscanf(file, "%31s %255s", ip_str, domain) == 2) {
        if (dns_entry_count >= MAX_ENTRIES) {
            fprintf(stderr, "DNS table is full, cannot add more entries.\n");
            break;
        }
        // Convert IP string to uint32_t
        if (inet_pton(AF_INET, ip_str, &dns_table[dns_entry_count].ip) != 1) {
            fprintf(stderr, "Invalid IP address format: %s\n", ip_str);
            continue;
        }
        // Store the IP address in network byte order
        dns_table[dns_entry_count].ip = ntohl(dns_table[dns_entry_count].ip);
        // Store the domain name
        if (strlen(domain) >= MAX_DOMAIN_LEN) {
            fprintf(stderr, "Domain name too long: %s\n", domain);
            continue;
        } 
        strncpy(dns_table[dns_entry_count].domain, domain, MAX_DOMAIN_LEN);
        dns_table[dns_entry_count].domain[MAX_DOMAIN_LEN - 1] = '\0'; // Ensure null termination
        // Increment the entry count
        printf("Loaded DNS entry: %s -> %s\n", domain, ip_str);
        dns_entry_count++;
    }
    fclose(file);
}

int find_local_ip(const char* qname, uint32_t* ip_out) {
    char qname_no_dot[MAX_DOMAIN_LEN];
    strncpy(qname_no_dot, qname, MAX_DOMAIN_LEN);
    size_t len = strlen(qname_no_dot);
    if (qname_no_dot[len - 1] == '.') qname_no_dot[len - 1] = '\0';

    for (int i = 0; i < dns_entry_count; ++i) {
        if (strcasecmp(dns_table[i].domain, qname_no_dot) == 0) {
            *ip_out = dns_table[i].ip;
            return 1;
        }
    }
    return 0;
}

int forward_query_to_dns_server(const uint8_t* query_buf, size_t query_len,
                                uint8_t* resp_buf, size_t* resp_len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct timeval timeout = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in dns_addr;
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(53);
    dns_addr.sin_addr.s_addr = inet_addr("8.8.8.8");

    if (sendto(fd, query_buf, query_len, 0, (struct sockaddr*)&dns_addr, sizeof(dns_addr)) < 0) {
        perror("sendto");
        close(fd);
        return -1;
    }

    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    ssize_t len = recvfrom(fd, resp_buf, 512, 0, (struct sockaddr*)&from, &from_len);
    if (len < 0) {
        perror("recvfrom (upstream DNS)");
        close(fd);
        return -1;
    }

    *resp_len = len;
    close(fd);
    return 0;
}

void insert_cached_entry(const char* domain, uint32_t ip) {
    if (dns_entry_count >= MAX_ENTRIES) return;
    strncpy(dns_table[dns_entry_count].domain, domain, MAX_DOMAIN_LEN);
    dns_table[dns_entry_count].ip = ip;
    dns_table[dns_entry_count].cached_time = time(NULL);
    dns_table[dns_entry_count].is_cached = 1;
    dns_entry_count++;
    FILE* f = fopen("dnsrelay.txt", "a");
    if (f) {
    fprintf(f, "%s %s\n", inet_ntoa(*(struct in_addr*)&ip), domain);
    fclose(f);
}

}




