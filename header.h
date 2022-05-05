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
#define MAXPACKETSIZE 2048

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

//===============================================
//               pkcs7_pad
//    pads the buffer inputted into fucntion
//===============================================
void pkcs7_pad(char *buf, int *data_len)
{
    uint8_t pad_len = AES_BLOCKLEN - ((*data_len) % AES_BLOCKLEN);
    for (int i = 0; i < pad_len; i++) {
        buf[(*data_len) + i] = pad_len;
    }
    (*data_len) += pad_len;
}

//===============================================
//               pkcs7_unpad
//    unpads the buffer inputted into fucntion
//===============================================
int pkcs7_unpad(char *buf, int *buf_len)
{
    // checks for error
    if ((*buf_len) % AES_BLOCKLEN != 0){
        fprintf(stderr, "pkcs7_unpad: invalid block size\n");
        return -1;
    }

    char pad_num = buf[(*buf_len) - 1];
    // check whether pad_num is bigger than AES_BLOCKLEN or not
    if (pad_num >= AES_BLOCKLEN){
        return 0;
    }

    for (int i = (*buf_len) - pad_num; i < (*buf_len); i++){
        if (buf[i] != pad_num){
            return 0;
        }
    }
    (*buf_len) -= pad_num;
    return 0;
}