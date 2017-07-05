default:
	gcc vanity.c -Ofast -lcrypto -lkeccak -lpthread -o  vanity
