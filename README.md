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
The file `client.c` contains our implementation for the client system. We first define a helper function `send_url()` that sends a packet to the server containing the URL or hostname of the HTTP server that the client would like to connect to. The packet consists of a header and a URL field. The first byte of the header is the flag field. The flag field currently is by default always set to `0x01` as our implementation only supports one mode but this field is being included for possible expansion in the future. Next, the header contains the 2 byte length of the url field in network byte order. Lastly, we append the URL specified by the user. Before the packet is sent off to the server, we also prepend the IV value to the start of the packet. The IV value, a 16 bytes values that we generate using a CSPRNG, is required for us to be able to properly decrypt the message using AES. Note that we generate a new IV value for each message that we send.

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
 
 Then the client sets up `poll()` allowing us to both send and receive data at the same time.
 
 ```c
    struct pollfd pfds[2];
    pfds[0].fd = 0;
    pfds[0].events = POLLIN;
    pfds[1].fd = sockfd;
    pfds[1].events = POLLIN;
 ```
 
The next step is to perform ECDH. We then set up and generate the required client side values like the private/public key. We receive the public key of the server and then send a copy of the client public key we just generated to the server as well. Using the server public key and our private key we generate a shared secret value that we hash using SHA256 to create a shared AES key that we will later use to encrypt all messages.
 
 ```c
 // Initialize CSPRNG
    CSPRNG rng = csprng_create();
    if (!rng) {
        fprintf(stderr, "error initializing CSPRNG\n");
        return 1;
    }

    // Initialize the client's keys
    static uint8_t cl_pub[ECC_PUB_KEY_SIZE];
    static uint8_t cl_prv[ECC_PRV_KEY_SIZE];

    // Generate client's private key
    csprng_get(rng, &cl_prv, ECC_PRV_KEY_SIZE);

    // Generate client's public key
    if (ecdh_generate_keys(cl_pub, cl_prv) != 1) {
        fprintf(stderr, "error generating client's public key\n");
        return 1;
    }

    // Receiving the server's public key
    uint8_t srv_pub[ECC_PUB_KEY_SIZE];
    if (recv(sockfd, srv_pub, ECC_PUB_KEY_SIZE, 0) == -1){
        perror("recv");
        return 1;
    }

    // prints srv_pub
    printf("srv_pub: ");
    print_hex_uint8(srv_pub, ECC_PUB_KEY_SIZE);

    // Send client's public key to server
    if (send(sockfd, cl_pub, ECC_PUB_KEY_SIZE, 0) == -1){
        perror("send");
        return 1;
    }

    // prints cl_pub
    printf("cl_pub: ");
    print_hex_uint8(cl_pub, ECC_PUB_KEY_SIZE);

    // Generate shared secret
    static uint8_t shared_secret[ECC_PUB_KEY_SIZE];
    if (ecdh_shared_secret(cl_prv, srv_pub, shared_secret) != 1) {
        fprintf(stderr, "error generating shared secret\n");
        return 1;
    }

    // print shared secret
    printf("shared secret: ");
    print_hex_uint8(shared_secret, ECC_PUB_KEY_SIZE);

    // Generate AES key
    SHA256_CTX sha256_ctx;
    BYTE aes_key[SHA256_BLOCK_SIZE];
    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, shared_secret, ECC_PUB_KEY_SIZE);
    sha256_final(&sha256_ctx, aes_key);
```

The client also opens a log file to record all of the data that it receives from the server.

```c
    FILE *log_file = fopen("main.html", "wb");
    if (log_file == NULL){
        fprintf(stderr, "error opening log file\n");
        return 1;
    }
```

The client then enters an infinite loop, sending data when STDIN is ready, and receiving data when the server sends anything. When the server shuts down, the client also gracefully exits.

```c
    int poll_count;

    for(;;)
    {
        // checks for poll error
        if ((poll_count = poll(pfds, 2, -1)) == -1)
        {
            perror("[Client] poll");
            exit(1);
        }

        // if stdin ready
        if (pfds[0].revents & POLLIN)
        {
            // Grabs the input into the terminal
            if (fgets(buf, MAXDATASIZE, stdin) == NULL)
            {
                perror("[Client] fgets");
                exit(1);
            }
            buf[strlen(buf) - 1] = '\0'; // remove newline

            // generate IV
            uint8_t iv[AES_BLOCKLEN];
            csprng_get(rng, &iv, AES_BLOCKLEN);

            // send url to server
            if (send_url(sockfd, buf, aes_key, iv) == -1){
                exit(1);
            }
            
        }

        // if recvfrom ready
        if (pfds[1].revents & POLLIN)
        {
            // receives data and checks for error
            if ((numbytes = recv(sockfd, buf, MAXDATASIZE, 0)) == -1)
            {
                perror("[Client] recvfrom");
                exit(1);
            }
            // buffer[numbytes] = '\0';
            
            // Server closed connection
            if (numbytes == 0){
                printf("[Client] Server closed connection\n");
                break;
            }

            // get IV from buf
            uint8_t iv[AES_BLOCKLEN];
            memcpy(iv, buf, AES_BLOCKLEN);

            // get ciphertext from buf
            char buftext[numbytes - AES_BLOCKLEN];
            memcpy(buftext, buf + AES_BLOCKLEN, numbytes - AES_BLOCKLEN);
            numbytes -= AES_BLOCKLEN;

            // Decrypt the message
            struct AES_ctx aes_ctx;
            AES_init_ctx_iv(&aes_ctx, aes_key, iv);
            AES_CBC_decrypt_buffer(&aes_ctx, (uint8_t*)buftext, numbytes);

            // unpad the message
            if (pkcs7_unpad(buftext, &numbytes) == -1) {
                fprintf(stderr, "error unpadding message\n");
                exit(1);
            }

            // Print padded message
            printf("message: ");
            print_hex(buftext, numbytes);

            // Save to file
            fwrite(buftext, sizeof(char), numbytes, log_file);
            fflush(log_file);
        }
    }

    // Close socket and shutdown process
    rng = csprng_destroy(rng);
    close(sockfd);
    fclose(log_file);
```

# Server.c
The implementation for the server is much more complex compared to the client because it has to be able to handle multiple clients while keeping track of the nessecary information like encryption keys that is unique for each individual client. First we define the struct that we use to hold the client information.

```c
struct cl_info{
    uint8_t cl_pub[ECC_PUB_KEY_SIZE];
    uint8_t shr_key[ECC_PUB_KEY_SIZE];
    BYTE aes_key[SHA256_BLOCK_SIZE];
};
```


Next we introduce the different helper functions that we define. The first helper function, `get_listener_socket()` creates and binds a listener socket that we later require to set up TCP connections.

```c
int get_listener_socket(void)
{
    int listener;     // Listening socket descriptor
    int yes = 1;      // For setsockopt() SO_REUSEADDR
    int rv;

    struct addrinfo hints, *ai, *p;

    // Get us a socket and bind it
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if ((rv = getaddrinfo(NULL, TCP_PORT, &hints, &ai)) != 0) {
        fprintf(stderr, "selectserver: %s\n", gai_strerror(rv));
        exit(1);
    }
    
    for(p = ai; p != NULL; p = p->ai_next) {
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener < 0) { 
            continue;
        }
        
        // Lose the pesky "address already in use" error message
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

        if (bind(listener, p->ai_addr, p->ai_addrlen) < 0) {
            close(listener);
            continue;
        }

        break;
    }

    freeaddrinfo(ai); // All done with this

    // If we got here, it means we didn't get bound
    if (p == NULL) {
        return -1;
    }

    // Listen
    if (listen(listener, 10) == -1) {
        return -1;
    }

    return listener;
}
```

Next, we define `add_to_pfds()` and `del_from_pfds()` that add/removes new file descriptors as we accept/disconnect connections to/from the pfds struct. The poll pfds struct has to be dynamically allocated on the heap because we can accept any number of connections from clients.

```c
// Add a new file descriptor to the set
void add_to_pfds(struct pollfd *pfds[], int newfd, int *fd_count, int *fd_size)
{
    // If we don't have room, add more space in the pfds array
    if (*fd_count == *fd_size) {
        *fd_size *= 2; // Double it

        *pfds = realloc(*pfds, sizeof(**pfds) * (*fd_size));
    }

    (*pfds)[*fd_count].fd = newfd;
    (*pfds)[*fd_count].events = POLLIN; // Check ready-to-read

    (*fd_count)++;
}

// Remove an index from the set
void del_from_pfds(struct pollfd pfds[], int i, int *fd_count)
{
    // Copy the one from the end over this one
    pfds[i] = pfds[*fd_count-1];

    (*fd_count)--;
}
```

Very similar to `add_to_pfds()` and `del_from_pfds()`, the next two helper functions, `add_to_secs()` and `del_from_secs()` add/removes the client public key, shared key, and AES key from the client information struct.

```c
// Add new client secret to the list
void add_to_secs(struct cl_info *cl_secs[], uint8_t *cl_pub, uint8_t *shr_key, BYTE *aes_key, int *sec_count, int *sec_size)
{
    // If we don't have room, add more space in the cl_secs array
    if (*sec_count == *sec_size) {
        *sec_size *= 2; // Double it

        *cl_secs = realloc(*cl_secs, sizeof(**cl_secs) * (*sec_size));
    }
    
    memcpy((*cl_secs)[*sec_count].cl_pub, cl_pub, ECC_PUB_KEY_SIZE);
    memcpy((*cl_secs)[*sec_count].shr_key, shr_key, ECC_PUB_KEY_SIZE);
    memcpy((*cl_secs)[*sec_count].aes_key, aes_key, SHA256_BLOCK_SIZE);

    (*sec_count)++;   
}

// Remove client secret from the list
void del_from_secs(struct cl_info cl_secs[], int i, int *sec_count)
{
    // Copy the one from the end over this one
    cl_secs[i-1] = cl_secs[*sec_count-1];

    (*sec_count)--;
}
```

The `http_request()` function takes the URL specified by the client, sends an HTTP request to the URL, and saves the response in the char buffer defined as a parameter to the function.
```c
int http_request(char *response, int *response_len, int sender_fd, char *url)
{
    int sockfd, rv;
    struct addrinfo hints, *servinfo, *p;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(url, HTTP_PORT, &hints, &servinfo)) != 0){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and connect to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next){
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1){
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL){
        fprintf(stderr, "client: failed to connect\n");
        return -1;
    }

    freeaddrinfo(servinfo);
    
    char *request;
    if (asprintf(&request, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", url) == -1) {
        perror("asprintf");
        return -1;
    }
    printf("[socket %d] Making HTTP request to %s\n", sender_fd, url);

    if (send(sockfd, request, 27 + strlen(url), 0) == -1) {
        perror("send");
        return -1;
    }
    free(request);

    // read HTTP response
    if (((*response_len) = recv(sockfd, response, MAXDATASIZE-1, 0)) == -1) {
        perror("recv");
        return -1;
    }
    response[(*response_len)] = '\0';

    close(sockfd);

    return 0;
}
```

# Libs
We use four free open source libraries to support CSPRNG, ECDH, SHA256, and AES.
