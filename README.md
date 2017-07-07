# VanityGen

This is a simple but very fast vanity address generator for Ethereum-style secp256k1/keccak256 addresses.

I use the efficient endomorphism on secp256k1 described [here](https://bitcoin.stackexchange.com/questions/35814/how-do-you-derive-the-lambda-and-beta-values-for-endomorphism-on-the-secp256k1-c)
to approximately tripple the pubkeys tried per second.

Requires

   - GMP (Availible via apt, brew, etc.)

Checkout and build with

	git clone --recursive https://github.com/tjade273/VanityGen.git
	cd VanityGen
	make

Run as

    ./bin/vanity PREFIX [NUM_CORES]

For example

	./bin/vanity deadbeef 4
