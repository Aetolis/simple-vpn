all: client server

client:
	gcc -o client.out client.c -Wall -Werror

server:
	gcc -o server.out server.c -Wall -Werror

clean:
	rm -f client server *.out