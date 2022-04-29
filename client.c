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
//               sendInfo
//     send stuff to server
//===============================================
int sendInfo(int sockfd, char *url){

	char message[MAXDATASIZE];	
	memset(message, 0, MAXDATASIZE);

	// set message flag
	message[0] = 0x01;

	// set url length
	printf("%ld \n", strlen(url));
	uint16_t length = htons(strlen(url));
	memcpy(message + 1, &length, sizeof(uint16_t));

	// set url
	memcpy(message + 1 + sizeof(uint16_t), url, strlen(url));

	// printf("%d \n", length);
	// receive message from server
	if ((send(sockfd, message, 5 + strlen(url), 0)) == -1){
		perror("send");
		exit(1);
	}
	
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
    // int bytes_sent;

	int sockfd, numbytes, rv;
	struct addrinfo hints, *servinfo, *p;
	char s[INET6_ADDRSTRLEN];
	char buf[MAXDATASIZE];
	
	//construct initial message
	/*int i = 0;
	char msg[MAXDATASIZE];
	while(argv[2][i] != 0){
		msg[i] = argv[2][i];
		i++;
	}*/

	if (argc != 2){
		fprintf(stderr, "usage: client.out hostname\n");
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

	// setup poll
    struct pollfd pfds[2];
	pfds[0].fd = 0;
	pfds[0].events = POLLIN;
	pfds[1].fd = sockfd;
	pfds[1].events = POLLIN;

	freeaddrinfo(servinfo);

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
            printf("%ld \n", strlen(buf));
			sendInfo(sockfd, buf);
            // if ((numbytes = send(sockfd, buf, strlen(buf) - 1, 0)) == -1)
            // {
            //     perror("[Client] send");
            //     exit(1);
            // }
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

            // printf("%s: %s\n", other_username, buffer);
        }
    }

    close(sockfd);

    return 0;
}
