// client.c

#include "header.h"

//===============================================
//               sendInfo
//     send stuff to server
//===============================================
int send_url(int sockfd, char *url){
	char message[MAXDATASIZE];	
	memset(message, 0, MAXDATASIZE);

	// set message flag
	message[0] = 0x01;

	// set url length
	uint16_t length = htons(strlen(url));
	memcpy(message + 1, &length, sizeof(uint16_t));

	// set url
	memcpy(message + 1 + sizeof(uint16_t), url, strlen(url));

	// send message to server
	if ((send(sockfd, message, 5 + strlen(url), 0)) == -1){
		perror("send");
		return -1;
	}
	
	return 0;
}

int pkcs7_unpad(char *buf, int *buf_len){
	if ((*buf_len) % BLOCKSIZE != 0){
		fprintf(stderr, "pkcs7_unpad: invalid block size\n");
		return -1;
	}

	char pad_num = buf[(*buf_len) - 1];

	if (pad_num >= BLOCKSIZE){
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


//===============================================
//                  main
//===============================================
int main(int argc, char *argv[]){
	int sockfd, numbytes, rv;
	struct addrinfo hints, *servinfo, *p;
	char s[INET6_ADDRSTRLEN];
	char buf[MAXDATASIZE];

	if (argc != 2){
		fprintf(stderr, "usage: client.out hostname\n");
		exit(1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(argv[1], TCP_PORT, &hints, &servinfo)) != 0){
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
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
		return 2;
	}

	// Get the address of the server
	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof(s));
	printf("client: connecting to %s\n", s);

	// setup poll
    struct pollfd pfds[2];
	pfds[0].fd = 0;
	pfds[0].events = POLLIN;
	pfds[1].fd = sockfd;
	pfds[1].events = POLLIN;

	freeaddrinfo(servinfo);

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

	printf("srv_pub: ");
	print_hex_uint8(srv_pub, ECC_PUB_KEY_SIZE);

	// Send client's public key to server
	if (send(sockfd, cl_pub, ECC_PUB_KEY_SIZE, 0) == -1){
		perror("send");
		return 1;
	}

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
	SHA256_CTX ctx;
	BYTE aes_key[SHA256_BLOCK_SIZE];
	sha256_init(&ctx);
	sha256_update(&ctx, shared_secret, ECC_PUB_KEY_SIZE);
	sha256_final(&ctx, aes_key);

	printf("AES key: ");
	print_hex_byte(aes_key, SHA256_BLOCK_SIZE); 

	// Open log file
	FILE *log_file = fopen("main.html", "wb");
	if (log_file == NULL){
		fprintf(stderr, "error opening log file\n");
		return 1;
	}

	int poll_count;

	for(;;)
    {
        if ((poll_count = poll(pfds, 2, -1)) == -1)
        {
            perror("[Client] poll");
            exit(1);
        }

        // if stdin ready
        if (pfds[0].revents & POLLIN)
        {
            if (fgets(buf, MAXDATASIZE, stdin) == NULL)
            {
                perror("[Client] fgets");
                exit(1);
            }
            buf[strlen(buf) - 1] = '\0'; // remove newline

			// send url to server
			if (send_url(sockfd, buf) == -1){
				exit(1);
			}
            
        }

        // if recvfrom ready
        if (pfds[1].revents & POLLIN)
        {
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

			// Unencrypt the message
			struct AES_ctx aes_ctx;
			AES_init_ctx(&aes_ctx, aes_key);
			AES_CBC_decrypt_buffer(&aes_ctx, (uint8_t*)buf, numbytes);

			// unpad the message
			if (pkcs7_unpad(buf, &numbytes) == -1) {
				fprintf(stderr, "error unpadding message\n");
				exit(1);
			}

			// Print padded message
			printf("message: ");
			print_hex(buf, numbytes);

			// Save to file
			fwrite(buf, sizeof(char), numbytes, log_file);
		}
    }

	rng = csprng_destroy(rng);
    close(sockfd);
	fclose(log_file);

    return 0;
}
