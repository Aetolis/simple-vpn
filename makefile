all: client server

client:
	gcc -o client client.c -Wall -Werror

server:
	gcc -o server server.c -Wall -Werror

clean:
	rm -f client server