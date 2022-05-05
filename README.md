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
The file `client.c` contains our implementation for the client system. We first define a helper function `send_url()` that sends a packet to the server containing the URL or hostname of the HTTP server that the client would like to connect to. The packet consists of a header and a URL field. The first byte of the header is the flag field. The flag field currently is by default always set to `0x01` as our implementation only supports one mode but this field is being included for possible expansion in the future. Next, the header contains the 2 byte length of the url field in network byte order. Lastly, we append the URL specified by the user. Before the packet is sent off to the server, we also prepend the IV value to the start of the packet. The IV value, a 16 bytes values that we generate using a CSPRNG, is required for us to be able to properly decrypt the message using AES.

```c
int send_url(int sockfd, char *url, BYTE *aes_key, BYTE *aes_iv){
    char message[MAXPACKETSIZE];

    // set message flag
    message[0] = 0x01;

    // set url msg_len
    uint16_t url_msg_len = htons(strlen(url));
    memcpy(message + 1, &url_msg_len, sizeof(uint16_t));

    // set url
    memcpy(message + 1 + sizeof(uint16_t), url, strlen(url));

    // pad message
    int msg_len = 1 + sizeof(uint16_t) + strlen(url);
    pkcs7_pad(message, &msg_len);

    // encrypt message
    struct AES_ctx aes_ctx;
    AES_init_ctx_iv(&aes_ctx, aes_key, aes_iv);
    AES_CBC_encrypt_buffer(&aes_ctx, (uint8_t*)message, msg_len);

    // prepend IV to message
    char packet[msg_len + AES_BLOCKLEN];
    memcpy(packet, aes_iv, AES_BLOCKLEN);
    memcpy(packet + AES_BLOCKLEN, message, msg_len);

    // send message to server
    if ((send(sockfd, packet, msg_len + AES_BLOCKLEN, 0)) == -1){
        perror("send");
        return -1;
    }
    
    return 0;
}
```

In the main function of this program, the client first attempts to set up a TCP connection with the server and exits on failure.

```c
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(argv[1], TCP_PORT, &hints, &servinfo)) != 0){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next){
        // establishes socket
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
            perror("client: socket");
            continue;
        }

        // Establishes connection between client and server
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1){
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    // checks for client connection error
    if (p == NULL){
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    // Get the address of the server
    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof(s));
    printf("client: connecting to %s\n", s);
    ```
    
    

# Server.c

# Libs
We use three free open source libraries to support CSPRNG, ECDH, SHA256, and AES.
