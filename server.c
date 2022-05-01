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

#define TCP_PORT "9034"   // Port we're listening on
#define HTTP_PORT "80"
#define MAXDATASIZE 1024

struct cl_info{
    uint8_t cl_pub[ECC_PUB_KEY_SIZE];
    uint8_t shr_key[ECC_PUB_KEY_SIZE];
    BYTE aes_key[SHA256_BLOCK_SIZE];
};

// Get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

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
    cl_secs[i] = cl_secs[*sec_count-1];

    (*sec_count)--;
}

// Http request handler
int http_request(int sender_fd, char *url)
{
    int sockfd, numbytes, rv;
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
    printf("Making HTTP request to %s\n", url);

    if (send(sockfd, request, 27 + strlen(url), 0) == -1) {
        perror("send");
        return -1;
    }
    free(request);

    // read HTTP response
    char response[MAXDATASIZE];
    if ((numbytes = recv(sockfd, response, MAXDATASIZE-1, 0)) == -1) {
        perror("recv");
        return -1;
    }
    response[numbytes] = '\0';
    printf("%s\n", response);

    // send to client
    if (send(sender_fd, response, numbytes, 0) == -1) {
        perror("send");
        return -1;
    }

    close(sockfd);

    return 0;
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
        return 1;
    }

    // Initialize the server's keys
    static uint8_t serv_pub[ECC_PUB_KEY_SIZE];
    static uint8_t serv_prv[ECC_PRV_KEY_SIZE];

    // Generate server's private key
    csprng_get(rng, &serv_prv, ECC_PRV_KEY_SIZE);

    // Generate server's public key
    if (ecdh_generate_keys(serv_pub, serv_prv) != 1) {
        fprintf(stderr, "error generating keys\n");
        return 1;
    }

    // Initialize SHA256 context
    SHA256_CTX ctx;

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

                        printf("Server's public key: %s\n", serv_pub);

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
                        sha256_init(&ctx);
                        sha256_update(&ctx, shr_key, ECC_PUB_KEY_SIZE);
                        sha256_final(&ctx, aes_key);

                        // Add client secret to list
                        add_to_secs(&cl_secs, cl_pub, shr_key, aes_key, &sec_count, &sec_size);

                        // print client's public key
                        printf("Client public key: %s\n", cl_secs[sec_count-1].cl_pub);
                        printf("Shared secret: %s\n", cl_secs[sec_count-1].shr_key);
                        printf("AES key: %s\n", cl_secs[sec_count-1].aes_key);
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
                        //get flag
                        printf("flag: %d\n", buf[0]);

                        uint16_t data_len;
                        memcpy(&data_len, buf + 1, sizeof(uint16_t));
                        data_len = ntohs(data_len);
                        printf("data_len: %d\n", data_len);

                        char url[data_len];
                        memcpy(url, buf + 1 + sizeof(uint16_t), data_len);
                        url[data_len] = '\0';
                        printf("url: %s\n", url);

                        // HTTP request to url
                        if (http_request(sender_fd, url) == -1) {
                            printf("HTTP request failed\n");
                        }


                        for(int j = 0; j < fd_count; j++) {
                            // Send to everyone!
                            int dest_fd = pfds[j].fd;

                            // Except the listener and ourselves
                            if (dest_fd != listener) {
                                if (send(dest_fd, buf, nbytes, 0) == -1) {
                                    perror("send");
                                }
                            }
                        }
                    }
                } // END handle data from client
            } // END got ready-to-read from poll()
        } // END looping through file descriptors
    } // END for(;;)--and you thought it would never end!

    rng = csprng_destroy(rng);
    return 0;
}