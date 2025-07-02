CC = gcc
CFLAGS = -Iinclude -Wall -g
LDFLAGS = -lcmocka

# 主程序
SRC_DIR = src
TEST_DIR = test

SRCS = $(SRC_DIR)/dns_parser.c $(SRC_DIR)/dns_builder.c $(SRC_DIR)/dns_utils.c $(SRC_DIR)/dns_cache.c $(SRC_DIR)/dns_response_parser.c
OBJS = $(SRCS:.c=.o)

# 目标
all: dns_relay test_dns

dns_relay: main.o $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ 

test_dns: $(TEST_DIR)/test_dns.o $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f dns_relay test_dns *.o $(SRC_DIR)/*.o $(TEST_DIR)/*.o

.PHONY: all clean