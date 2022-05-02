all: client server

ecdh.o: libs/ecdh.c
	gcc -c libs/ecdh.c -I.

csprng.o: libs/csprng.c
	gcc -c libs/csprng.c -I.

sha256.o: libs/sha256.c
	gcc -c libs/sha256.c -I.

aes.o: libs/aes.c
	gcc -c libs/aes.c -I.

client: ecdh.o csprng.o sha256.o aes.o
	gcc -o client.out client.c ecdh.o csprng.o sha256.o aes.o -Wall -Werror -I.

server: ecdh.o csprng.o sha256.o aes.o
	gcc -o server.out server.c ecdh.o csprng.o sha256.o aes.o -Wall -Werror -I.

clean:
	rm -f client server *.out *.o *.html