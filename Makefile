default:
	mkdir -p bin
	gcc src/vanity.c -Ofast -lcrypto -lkeccak -lpthread -o bin/vanity
