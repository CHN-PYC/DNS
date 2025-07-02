#include "dns.h"
#include "cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

// DNS RCODE for SERVFAIL
#define DNS_RCODE_SERVFAIL 2

#define DNS_PORT 53
#define BUFFER_SIZE 512

void signal_handler(int sig)
{
    if (sig == SIGINT)
    {
        printf("\nShutting down DNS relay server...\n");
        exit(0);
    }
}

int main()
{
    signal(SIGINT, signal_handler);

    // 初始化DNS和缓存系统
    load_dns_table("dnsrelay.txt");
    init_cache();

    // 创建UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("Socket creation failed");
        return 1;
    }

    // 设置socket选项
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(DNS_PORT);

    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    // 绑定到DNS端口
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)))
    {
        perror("Bind failed");
        close(sockfd);
        return 1;
    }

    printf("DNS relay server started on port %d\n", DNS_PORT);
    printf("Cache size: %d entries\n", CACHE_SIZE);

    // 主循环处理查询
    while (1)
    {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        uint8_t buffer[BUFFER_SIZE];

        // 接收DNS查询
        ssize_t n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                             (struct sockaddr *)&cli_addr, &cli_len);
        if (n < 0)
        {
            perror("recvfrom failed");
            continue;
        }

        // 解析DNS查询
        dns_header_t header;
        dns_question_t question;
        if (parse_dns_query(buffer, n, &header, &question) != 0)
        {
            printf("Failed to parse DNS query\n");
            continue;
        }

        // 打印客户端信息
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("\nQuery from %s:%d for %s\n",
               client_ip, ntohs(cli_addr.sin_port), question.qname);

        uint8_t response[BUFFER_SIZE];
        size_t response_len = 0;
        uint32_t ip;

        // 处理三种查询情况
        if (find_local_ip(question.qname, &ip))
        {
            // Case 1: 本地数据库中有记录
            if (ip == inet_addr("0.0.0.0"))
            {
                printf("[Local] Blocking %s (NXDOMAIN)\n", question.qname);
                build_error_response(&header, question.qname,
                                     response, &response_len, DNS_RCODE_NXDOMAIN);
            }
            else
            {
                struct in_addr ip_addr;
                ip_addr.s_addr = ntohl(ip); // 转为主机字节序
                printf("Local IP found for %s: %s\n", question.qname, inet_ntoa(ip_addr));
                build_a_response(&header, question.qname,
                                 ip, response, &response_len);
            }
        }
        else if (find_in_cache(question.qname, &ip))
        {
            // Case 2: 缓存中有记录
            struct in_addr ip_addr;
            ip_addr.s_addr = ip;
            printf("[Cache] Resolved %s -> %s\n",
                   question.qname, inet_ntoa(ip_addr));
            build_a_response(&header, question.qname,
                             ip, response, &response_len);
        }
        else
        {
            // Case 3: 需要转发查询
            printf("[Forward] Querying upstream for %s\n", question.qname);

            if (forward_query_to_dns_server(buffer, n, response, &response_len) != 0)
            {
                printf("[Error] Forwarding failed, returning SERVFAIL\n");
                build_error_response(&header, question.qname,
                                     response, &response_len, DNS_RCODE_SERVFAIL);
            }
            else
            {
                
                //insert_cached_entry(question.qname, ntohl(*(uint32_t *)(response + sizeof(dns_header_t) + 12)));
                // 解析并缓存响应
                uint32_t response_ip, ttl;
                if (parse_dns_response_for_cache(response, response_len, &response_ip, &ttl))
                {
                    insert_into_cache(question.qname, response_ip, ttl);
                    struct in_addr ip_addr;
                    ip_addr.s_addr = response_ip;
                    printf("[Cache] Added %s -> %s (TTL: %u)\n",
                           question.qname, inet_ntoa(ip_addr), ttl);
                }
            }
        }

        // 发送响应
        if (sendto(sockfd, response, response_len, 0,
                   (struct sockaddr *)&cli_addr, cli_len) < 0)
        {
            perror("sendto failed");
        }

        free(question.qname);
    }

    close(sockfd);
    return 0;
}