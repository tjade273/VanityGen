default:
	mkdir -p bin
	gcc src/vanity.c -Ofast -Wno-unused-result -lcrypto -lkeccak -lpthread -lsecp256k1 -o bin/vanity
install:
	cp bin/vanity /usr/local/bin/vanity
