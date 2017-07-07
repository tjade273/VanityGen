CC=gcc
IDIRS=-Isecp256k1/include -Isecp256k1 -Ilibkeccak/src
LDIRS=-Lsecp256k1/src -Lsecp256k1 -Llibkeccak/bin
LIBS=-lgmp -lsecp256k1 -lpthread libkeccak/bin/libkeccak.a
CFLAGS=$(IDIRS) $(LDIRS) $(LIBS)
DEPS=src/vanity.c secp256k1/src/libsecp256k1-config.h secp256k1/src/ecmult_static_context.h libkeccak/bin/libkeccak.a

vanity: $(DEPS)
	mkdir -p bin
	$(CC) src/vanity.c -Ofast -Wno-unused-result -funsafe-loop-optimizations $(CFLAGS) -o bin/vanity
install:
	cp bin/vanity /usr/local/bin/vanity

secp256k1/src/libsecp256k1-config.h:
	(cd secp256k1;./autogen.sh;./configure --enable-endomorphism)


secp256k1/src/ecmult_static_context.h:
	$(MAKE) -C secp256k1 src/ecmult_static_context.h

libkeccak/bin/libkeccak.a:
	$(MAKE) -C libkeccak lib
