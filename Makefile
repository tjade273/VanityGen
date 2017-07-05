default:
	mkdir -p bin
	gcc src/vanity.c -Ofast -lcrypto -lkeccak -lpthread -o bin/vanity
install:
	cp bin/vanity /usr/local/bin/vanity
