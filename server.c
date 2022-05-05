// server.c

#include "header.h"

struct cl_info{
    uint8_t cl_pub[ECC_PUB_KEY_SIZE];
    uint8_t shr_key[ECC_PUB_KEY_SIZE];
    BYTE aes_key[SHA256_BLOCK_SIZE];
};

// Return a listening socket
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

// Http request handler
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

// PKCS#7 padding
void pkcs7_pad(char *buf, int *data_len)
{
    uint8_t pad_len = BLOCKSIZE - ((*data_len) % BLOCKSIZE);
    for (int i = 0; i < pad_len; i++) {
        buf[(*data_len) + i] = pad_len;
    }
    (*data_len) += pad_len;
}

// Main
int main(void)
{
    int listener;     // Listening socket descriptor

    int newfd;        // Newly accept()ed socket descriptor
    struct sockaddr_storage remoteaddr; // Client address
    socklen_t addrlen;

    char buf[256];    // Buffer for client data

    char remoteIP[INET6_ADDRSTRLEN];

    // Start off with room for 5 connections
    // (We'll realloc as necessary)
    int fd_count = 0;
    int fd_size = 5;
    struct pollfd *pfds = malloc(sizeof(*pfds) * fd_size);

    // Set up and get a listening socket
    listener = get_listener_socket();

    if (listener == -1) {
        fprintf(stderr, "error getting listening socket\n");
        exit(1);
    }

    // Add the listener to set
    pfds[0].fd = listener;
    pfds[0].events = POLLIN; // Report ready to read on incoming connection

    fd_count = 1; // For the listener

    // Start off with room for 5 client secrets
    int sec_count = 0;
    int sec_size = 5;
    struct cl_info *cl_secs = malloc(sizeof(*cl_secs) * sec_size);

    // Initialize CSPRNG
    CSPRNG rng = csprng_create();
    if (!rng) {
        fprintf(stderr, "error initializing CSPRNG\n");
        exit(1);
    }

    // Initialize the server's keys
    static uint8_t serv_pub[ECC_PUB_KEY_SIZE];
    static uint8_t serv_prv[ECC_PRV_KEY_SIZE];

    // Generate server's private key
    csprng_get(rng, &serv_prv, ECC_PRV_KEY_SIZE);

    // Generate server's public key
    if (ecdh_generate_keys(serv_pub, serv_prv) != 1) {
        fprintf(stderr, "error generating keys\n");
        exit(1);
    }
    printf("serv_pub: ");
    print_hex_uint8(serv_pub, ECC_PUB_KEY_SIZE);

    // Initialize SHA256 context
    SHA256_CTX sha256_ctx;

    // Main loop
    for(;;) {
        int poll_count = poll(pfds, fd_count, -1);

        if (poll_count == -1) {
            perror("poll");
            exit(1);
        }

        // Run through the existing connections looking for data to read
        for(int i = 0; i < fd_count; i++) {

            // Check if someone's ready to read
            if (pfds[i].revents & POLLIN) { // We got one!!

                if (pfds[i].fd == listener) {
                    // If listener is ready to read, handle new connection

                    addrlen = sizeof(remoteaddr);
                    newfd = accept(listener, (struct sockaddr *)&remoteaddr, &addrlen);

                    if (newfd == -1) {
                        perror("accept");
                    } else {
                        add_to_pfds(&pfds, newfd, &fd_count, &fd_size);

                        // Send server public key to client
                        if (send(newfd, serv_pub, ECC_PUB_KEY_SIZE, 0) == -1) {
                            perror("send");
                            return 1;
                        }

                        

                        // Receive client public key from client
                        uint8_t cl_pub[ECC_PUB_KEY_SIZE];
                        if (recv(newfd, cl_pub, ECC_PUB_KEY_SIZE, 0) == -1) {
                            perror("recv");
                            return 1;
                        }

                        // Generate shared secret
                        static uint8_t shr_key[ECC_PUB_KEY_SIZE];
                        if (ecdh_shared_secret(serv_prv, cl_pub, shr_key) != 1) {
                            fprintf(stderr, "error generating shared secret\n");
                            return 1;
                        }

                        // Generate AES key
                        BYTE aes_key[SHA256_BLOCK_SIZE];
                        sha256_init(&sha256_ctx);
                        sha256_update(&sha256_ctx, shr_key, ECC_PUB_KEY_SIZE);
                        sha256_final(&sha256_ctx, aes_key);

                        // Add client secret to list
                        add_to_secs(&cl_secs, cl_pub, shr_key, aes_key, &sec_count, &sec_size);

                        
                        printf("[socket %d] establishing ECDH...\n", newfd);
                        printf("cl_pub: ");
                        print_hex_uint8(cl_secs[sec_count-1].cl_pub, ECC_PUB_KEY_SIZE);

                        printf("shr_key: ");
                        print_hex_uint8(cl_secs[sec_count-1].shr_key, ECC_PUB_KEY_SIZE);

                        printf("aes_key: ");
                        print_hex_uint8(cl_secs[sec_count-1].aes_key, SHA256_BLOCK_SIZE);

                        // if (memcmp(aes_key, cl_secs[sec_count-1].aes_key, SHA256_BLOCK_SIZE) != 0) {
                        //     fprintf(stderr, "error generating AES key\n");
                        //     return 1;
                        // }

                        printf("pollserver: new connection from %s on socket %d\n", inet_ntop(remoteaddr.ss_family, get_in_addr((struct sockaddr*)&remoteaddr), remoteIP, INET6_ADDRSTRLEN), newfd);
                    }
                } else {
                    // If not the listener, we're just a regular client
                    int nbytes = recv(pfds[i].fd, buf, sizeof(buf), 0);

                    int sender_fd = pfds[i].fd;

                    if (nbytes <= 0) {
                        // Got error or connection closed by client
                        if (nbytes == 0) {
                            // Connection closed
                            printf("pollserver: socket %d hung up\n", sender_fd);
                        } else {
                            perror("recv");
                        }

                        close(pfds[i].fd); // Bye!

                        del_from_pfds(pfds, i, &fd_count);
                        del_from_secs(cl_secs, i, &sec_count);

                    } else {    // data received from client
                        uint16_t data_len;
                        memcpy(&data_len, buf + 1, sizeof(uint16_t));
                        data_len = ntohs(data_len);

                        char url[data_len];
                        memcpy(url, buf + 1 + sizeof(uint16_t), data_len);
                        url[data_len] = '\0';

                        // HTTP request to url
                        char response[MAXDATASIZE];
                        int response_len;
                        if (http_request(response, &response_len, sender_fd, url) == -1) {
                            printf("HTTP request failed\n");
                        }

                        // printf("%s\n", response);
                        print_hex(response, response_len);

                        // Pad response using PKCS#7
                        pkcs7_pad(response, &response_len);

                        // Encrypt response using AES
                        struct AES_ctx aes_ctx;
                        AES_init_ctx(&aes_ctx, cl_secs[i-1].aes_key);
                        AES_CBC_encrypt_buffer(&aes_ctx, (uint8_t*)response, response_len);

                        // send to client
                        if (send(sender_fd, response, response_len, 0) == -1) {
                            perror("send");
                            return -1;
                        }

                        // for(int j = 0; j < fd_count; j++) {
                        //     // Send to everyone!
                        //     int dest_fd = pfds[j].fd;

                        //     // Except the listener and ourselves
                        //     if (dest_fd != listener) {
                        //         if (send(dest_fd, buf, nbytes, 0) == -1) {
                        //             perror("send");
                        //         }
                        //     }
                        // }
                    }
                } // END handle data from client
            } // END got ready-to-read from poll()
        } // END looping through file descriptors
    } // END for(;;)--and you thought it would never end!

    rng = csprng_destroy(rng);
    return 0;
}