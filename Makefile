default:
	mkdir -p bin
	gcc src/vanity.c -Ofast -Wno-unused-result -Isecp256k1/include -Isecp256k1 -Lsecp256k1/src -Lsecp256k1 -lgmp -lsecp256k1 -lkeccak -lpthread  -o bin/vanity
install:
	cp bin/vanity /usr/local/bin/vanity
