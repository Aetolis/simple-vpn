// client.c

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

#define PORT "9034"
#define MAXDATASIZE 1024

//===============================================
//               receive
//     receive information from server
//===============================================
int receive(int sockfd){
	char buffer[1024];

	int numbytes = recv(sockfd, buffer, sizeof buffer, 0);
	if (numbytes == -1){
		perror("recv");
		exit(1);
	}

  	// char flag;
	// short len = 0;
	// char url[len];

	return 0;
}



//===============================================
//               receive
//     send stuff to server
//===============================================
int sendInfo(int sockfd){

	return 0;
}


void *get_in_addr(struct sockaddr *sa){
	if (sa->sa_family == AF_INET){
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


//===============================================
//                  main
//===============================================
int main(int argc, char *argv[]){
    int LISTENING = 1;
    // int bytes_sent;

	int sockfd, numbytes, rv;
	struct addrinfo hints, *servinfo, *p;
	char s[INET6_ADDRSTRLEN];
	char buf[MAXDATASIZE];

	if (argc != 3){
		fprintf(stderr, "usage: client hostname address\n");
		exit(1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0){
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

	freeaddrinfo(servinfo);

	// Send the message to the server
	printf("%s \n %s \n", argv[1], argv[2]);

	char *msg = argv[2];

	numbytes = send(sockfd, msg, sizeof(msg), 0);

	// receive message from server
	if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1){
		perror("recv");
		exit(1);
	}

	buf[numbytes] = '\0';

	printf("client: received '%s'\n", buf);

    struct pollfd pfds[2];
    while (LISTENING == 1){
        //char buffer[1024];
        // struct sockaddr_storage sender_addr;      // sender's address (may be IPv6)
		// socklen_t addr1_len = sizeof sender_addr;  // length of this address

        pfds[0].fd = sockfd;
				pfds[0].events = POLLIN;

				pfds[1].fd = 0; //cin
				pfds[1].events = POLLIN;

        int num_events = poll(pfds, 2, -1);
        if (num_events != 0){
            int pollin_happened1 = pfds[0].revents & POLLIN;
						int pollin_happened2 = pfds[1].revents & POLLIN;
            if (pollin_happened1){
                receive(sockfd);
            }
						else if (pollin_happened2){
								//sendInfo(sockfd);
								char message[MAXBUFLEN];

								fgets(message, MAXBUFLEN, stdin);
								int size = strlen(message);
								message[size-1] = '\0';

						}
        }
    }

    close(sockfd);

    return 0;
}
