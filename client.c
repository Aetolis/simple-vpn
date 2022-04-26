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

#define PORT 9034


//===============================================
//               makeSocket
//     create socket for receiving info
//===============================================
struct sockaddr_in makeSocket(void){
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	memset(server_addr.sin_zero, 0, sizeof server_addr.sin_zero);

	return server_addr;
}


//===============================================
//                  main
//===============================================
int main(int argc, char **argv){

    int LISTENING = 1;

    //ESTABLISH SOCKET
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
      perror("client: socket failed");
      exit(0);
    }

    struct sockaddr_in server_addr = makeSocket();	//fill in socket ids
    connect(sockfd, server_addr, sizeof server_addr); //handles connection and bind

    struct pollfd pfds[1];
    while (LISTENING == 1){
        char buffer[1024];
        struct sockaddr_storage sender_addr;      // sender's address (may be IPv6)
		socklen_t addr1_len = sizeof sender_addr;  // length of this address

        pfds[0].fd = sockfd;
		pfds[0].events = POLLIN;

        int num_events = poll(pfds, 2, -1);
        if (num_events != 0){
            int pollin_happened = pfds[0].revents & POLLIN;
            if (pollin_happened){
                char buffer[1024];
                int numbytes = recv(sockfd, buffer, sizeof buffer, 0);
            }
        }
    }

    close(sockfd);

    return 0;
}