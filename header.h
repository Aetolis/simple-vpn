#pragma once
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <libs/csprng.h>
#include <libs/ecdh.h>
#include <libs/sha256.h>
#include <libs/aes.h>

#define TCP_PORT "9034"   // Port we're listening on
#define HTTP_PORT "80"
#define MAXDATASIZE 1024
#define BLOCKSIZE 16

void print_hex(const char *msg, int len)
{
    for (int i = 0; i < len; i++)
        printf("%02x", (unsigned char)msg[i]);
    printf("\n");
}

void print_hex_byte(BYTE *msg, int len)
{
    for (int i = 0; i < len; i++)
        printf("%02x", msg[i]);
    printf("\n");
}

void print_hex_uint8(uint8_t *msg, int len)
{
    for (int i = 0; i < len; i++)
        printf("%02x", msg[i]);
    printf("\n");
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET){
	return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
