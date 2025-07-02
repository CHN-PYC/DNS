#include "dns.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>

void test_parse_query(void** state) {
    // 测试代码保持不变...
    uint8_t sample_query[] = {
        /* Header */ 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Domain */ 0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        /* Qtype */ 0x00, 0x01, /* Qclass */ 0x00, 0x01
    };

    dns_header_t header;
    dns_question_t question;
    int ret = parse_dns_query(sample_query, sizeof(sample_query), &header, &question);

    assert_int_equal(ret, 0);
    assert_int_equal(header.id, 0x1234);
    assert_string_equal(question.qname, "www.example.com");
    assert_int_equal(question.qtype, 1); // A记录
    
    // 释放分配的内存
    free(question.qname);
}

void test_build_nxdomain(void** state) {
    // 测试代码保持不变...
    uint8_t sample_query[] = {
        /* Header */ 0x56, 0x78, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Domain */ 0x04, 't', 'e', 's', 't', 0x03, 'c', 'o', 'm', 0x00,
        /* Qtype */ 0x00, 0x01, /* Qclass */ 0x00, 0x01
    };
    
    dns_header_t req_header;
    memcpy(&req_header, sample_query, sizeof(dns_header_t));
    req_header.id = ntohs(req_header.id);
    
    uint8_t resp[512];
    size_t resp_len;
    build_nxdomain_response(&req_header, sample_query, sizeof(sample_query), resp, &resp_len);

    dns_header_t* resp_header = (dns_header_t*)resp;
    assert_int_equal(ntohs(resp_header->flags), 0x8183); // 验证RCODE=3
    assert_int_equal(ntohs(resp_header->qdcount), 1); // 问题数应为1
}

void test_build_a_response(void** state) {
    // 测试代码保持不变...
   dns_header_t req_header = { .id = 0x9ABC, .qdcount = 1 };
    uint8_t resp[512];
    size_t resp_len;

    build_a_response(&req_header, "test.com", 0x01020304, resp, &resp_len);

    // 验证响应长度至少大于头部+问题部分
    assert_true(resp_len > sizeof(dns_header_t) + 10);
    
    // 验证IP地址 (在响应末尾)
    uint32_t ip_in_resp;
    memcpy(&ip_in_resp, resp + resp_len - 4, 4);
    assert_int_equal(ntohl(ip_in_resp), 0x01020304);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_query),
        cmocka_unit_test(test_build_nxdomain),
        cmocka_unit_test(test_build_a_response),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}