# simple-vpn
This repository contains a simple implementation of a client to server virtual private network or proxy service written in C. All connections are handled by TCP and are end to end encrypted using AES. 

# Makefile
Use `make` or `make all` to compile the program and all its dependencies.

```makefile
all: client server

ecdh.o: libs/ecdh.c
    gcc -c libs/ecdh.c -I.

csprng.o: libs/csprng.c
    gcc -c libs/csprng.c -I.

sha256.o: libs/sha256.c
    gcc -c libs/sha256.c -I.

aes.o: libs/aes.c
    gcc -c libs/aes.c -I.

client: ecdh.o csprng.o sha256.o aes.o
    gcc -o client.out client.c ecdh.o csprng.o sha256.o aes.o -Wall -Werror -I.

server: ecdh.o csprng.o sha256.o aes.o
    gcc -o server.out server.c ecdh.o csprng.o sha256.o aes.o -Wall -Werror -I.

clean:
    rm -f *.out *.o *.html
```

The `make` command outputs the object files for each library in addition to two executable programs named `./client.out` and `./server.out`.

# Testing
To test the code, first start the server by using the following command: `./server.out`, which does not take any parameters. Next, to start the client run `./client.out <hostname>`, replacing `<hostname>` with the hostname of the server. Note that the server is able to handle multiple clients simultaneously so it is possible to have more than one client connected to the server at the same time. Finally, on the client side, input the hostname or IP of the HTTP webserver on the command line and press enter. The client should forward the request to the server and save the return message to disk. Both the client and server are verbose, printing out intermediary values for transparency.

# Header.h
In the shared header file, we include the nessecary library headers, define macros, and shared helper functions.

We define, `print_hex()`, `print_hex_byte()`, and `print_hex_uint8()` to output the `msg` buffer to `stdout` in hexadecimal format. All three of these functions follow the same basic implementation as shown below, except that the data type of the `msg` parameter differs in each case.
```c
void print_hex(const char *msg, int len)
{
    for (int i = 0; i < len; i++)
        printf("%02x", (unsigned char)msg[i]);
    printf("\n");
}
```

Additionally, we also define `get_in_addr()`, a helper function we use to setup our TCP connections.
```c
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET){
    return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
```

Lastly, we define the helper functions `pkcs7_pad()` and `pkcs7_unpad()` which implements padding for our `char` buffers as specified by [PKCS#7](https://datatracker.ietf.org/doc/html/rfc2315).

```c
void pkcs7_pad(char *buf, int *data_len)
{
    uint8_t pad_len = AES_BLOCKLEN - ((*data_len) % AES_BLOCKLEN);
    for (int i = 0; i < pad_len; i++) {
        buf[(*data_len) + i] = pad_len;
    }
    (*data_len) += pad_len;
}
```

```c
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
```

# Client.c

# Server.c

# Libs
We use three free open source libraries to support CSPRNG, ECDH, SHA256, and AES.
