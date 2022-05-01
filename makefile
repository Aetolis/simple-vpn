all: client server

ecdh.o: ecdh.c
	gcc -c ecdh.c -I.

csprng.o: csprng.c
	gcc -c csprng.c -I.

client: ecdh.o csprng.o
	gcc -o client.out client.c ecdh.o csprng.o -Wall -Werror -I.

server: ecdh.o csprng.o
	gcc -o server.out server.c ecdh.o csprng.o -Wall -Werror -I.

clean:
	rm -f client server *.out *.o