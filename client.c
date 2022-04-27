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

#define PORTS 9034
#define PORT "9034"


//===============================================
//               makeSocket
//     create socket for receiving info
//===============================================
struct sockaddr_in makeSocket(void){
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORTS);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	memset(server_addr.sin_zero, 0, sizeof server_addr.sin_zero);

	return server_addr;
}

//===============================================
//               receive
//     receive information from server
//===============================================
int receive(int sockfd){
	char buffer[1024];

	int numbytes = recv(sockfd, buffer, sizeof(buffer), 0);
	if (numbytes == -1){
		perror("recv");
		exit(1);
	}

  FILE *file = fopen("received", "w");
	int results = fputs(buffer, file);
	if (results == EOF){
		perror("write to file");
		exit(1);
	}
	fclose(file);

	return 0;
}



//===============================================
//               receive
//     send stuff to server
//===============================================
int sendInfo(int sockfd){

	return 0;
}


//===============================================
//                  main
//===============================================
int main(int argc, char **argv){

	struct addrinfo hints, *res;
 	int sockfd, LISTENING = 1;

	memset(&hints, 0 ,sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	getaddrinfo(argv[1], PORT, &hints, &res);
	
	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

	connect(sockfd, res->ai_addr, res->ai_addrlen);

	char *msg = argv[2];

    int bytes_sent = send(sockfd, msg, sizeof(msg), 0);
    	
    printf("%d \n", bytes_sent);



    struct pollfd pfds[1];
    while (LISTENING == 1){
        char buffer[1024];
        struct sockaddr_storage sender_addr;      // sender's address (may be IPv6)
				socklen_t addr1_len = sizeof sender_addr;  // length of this address

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
								sendInfo(sockfd);
						}
        }
    }
	
    close(sockfd);

    return 0;
}
