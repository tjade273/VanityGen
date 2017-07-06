CC=gcc
IDIRS=-Isecp256k1/include -Isecp256k1
LDIRS=-Lsecp256k1/src -Lsecp256k1
LIBS=-lgmp -lsecp256k1 -lkeccak -lpthread
CFLAGS=$(IDIRS) $(LDIRS) $(LIBS)

vanity: src/vanity.c secp256k1/src/libsecp256k1-config.h secp256k1/src/ecmult_static_context.h
	mkdir -p bin
	$(CC) src/vanity.c -Ofast -Wno-unused-result -funsafe-loop-optimizations $(CFLAGS) -o bin/vanity
install:
	cp bin/vanity /usr/local/bin/vanity

secp256k1/src/libsecp256k1-config.h:
	(cd secp256k1;./autogen.sh;./configure --enable-endomorphism)


secp256k1/src/ecmult_static_context.h:
	$(MAKE) -C secp256k1 src/ecmult_static_context.h
