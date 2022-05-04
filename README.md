# simple-vpn
This repository contains a simple implementation of a client to server virtual private network or proxy service written in C. All connections are handled by TCP and are end to end encrypted using AES.

# Makefile
Use `make` or `make all` to compile the program and all its dependencies.

```makefile
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
	rm -f *.out *.o *.html
```

The `make` command outputs the object files for each library in addition to two executable programs named `./client.out` and `./server.out`.

# Header.h
In the shared header file, we include the nessecary library headers, define macros, and shared helper functions.

We define, `print_hex()`, `print_hex_byte()`, and `print_hex_uint8()` to output the `msg` buffer to `stdout` in hexadecimal format. All three of these functions follow the same basic implementation as shown below, except that the data type of the `msg` parameter differs in each case.
```c
void print_hex(const char *msg, int len)
{
    for (int i = 0; i < len; i++)
        printf("%02x", (unsigned char)msg[i]);
    printf("\n");
}
```

Additionally, we also define `get_in_addr()`, a helper function we use to setup our TCP connections.
```c
void *get_in_addr(struct sockaddr *sa){
	if (sa->sa_family == AF_INET){
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
```

# Client.c

# Server.c

# Libs
We use three free open source libraries to support CSPRNG, ECDH, SHA256, and AES.
