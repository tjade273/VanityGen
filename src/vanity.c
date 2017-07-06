#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/random.h>

#define STEP 3072
#include "src/libsecp256k1-config.h"
#include "src/secp256k1.c"
#include "libkeccak.h"


#define ascii_to_byte(chr) (chr % 32 + 9) % 25

int finished = 0;

unsigned char *target;
int target_size;

libkeccak_spec_t spec;

static const unsigned char secp256k1_scalar_consts_lambda[32] = {
         0x53,0x63,0xad,0x4c,0xc0,0x5c,0x30,0xe0,
         0xa5,0x26,0x1c,0x02,0x88,0x12,0x64,0x5a,
         0x12,0x2e,0x22,0xea,0x20,0x81,0x66,0x78,
	 0xdf,0x02,0x96,0x7c,0x1b,0x23,0xbd,0x72
};


unsigned char *get_target(char* hex, int *size){
  int len = strlen(hex);
  unsigned char *buffer = malloc(len/2 + len % 2);
  for(int i = 0; i < len; i+=2){
    buffer[i/2] = ascii_to_byte(hex[i])*16 + ascii_to_byte(hex[i+1]);
  }
  if(len % 2 == 1){
    buffer[len/2] = ascii_to_byte(hex[len-1])*16;
  }
  *size = len;
  return buffer;
}

void print_keys(unsigned char *address, unsigned char *privkey){
  int i = 0;
  printf("Address: ");
  for(i = 12; i < 32; i++){
    printf("%02x", address[i]);
  }
  printf("\nPrivate Key: ");
  for(i = 0; i<32; i++){
    printf("%02x", privkey[i]);
  }
  printf("\n");
}

int hexcmp(unsigned char *a, unsigned char *b, int hexlen){
  int c = memcmp(a, b, hexlen/2);
  if(c != 0 || hexlen % 2 == 0){
    return c;
  }
  else {
    return !(a[hexlen/2] >> 4 ==  b[hexlen/2] >> 4);
  }
}

void *generate_address(void *ptr){

  unsigned long long *counter = ((unsigned long long *) ptr);
  libkeccak_state_t *state = libkeccak_state_create(&spec);

  unsigned char address[32];
  unsigned char public_key[65];
  size_t publen = 65;

  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
  secp256k1_pubkey pub;
  unsigned char prv[32];
  getrandom(prv, 32, 0);
  secp256k1_ec_pubkey_create(ctx, &pub, prv);
  const unsigned char tweak[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
  secp256k1_ge p;

  do {
    if(*counter % 3 == 0){
      secp256k1_ec_privkey_tweak_add(ctx, prv, tweak);
      secp256k1_ec_pubkey_tweak_add(ctx, &pub, tweak);
    }
    secp256k1_pubkey_load(ctx, &p, &pub);
    secp256k1_ge_mul_lambda(&p, &p);
    secp256k1_pubkey_save(&pub, &p);
    secp256k1_ec_privkey_tweak_mul(ctx, prv, secp256k1_scalar_consts_lambda);
    secp256k1_ec_pubkey_serialize(ctx, public_key, &publen, &pub, SECP256K1_EC_UNCOMPRESSED);

    libkeccak_state_reset(state);
    libkeccak_fast_update(state, public_key+1, 64);
    libkeccak_fast_digest(state, NULL, 0, 0, NULL, address);
    *counter = *counter+1;
  } while(hexcmp(address+12, target, target_size) != 0 && !finished);

  if(hexcmp(address+12, target, target_size) == 0){
    finished = 1;
    print_keys(address, prv);
  }
  secp256k1_context_destroy(ctx);
  libkeccak_state_fast_free(state);
}


int main(int argc, char* argv[]){

  int cores;

  if(argc == 2){
    cores = sysconf(_SC_NPROCESSORS_ONLN);
  }
  else if(argc == 3){
    cores = atoi(argv[2]);
  }
  else{
    printf("usage: vanity prefix [ncores]\n");
    exit(1);
  }

  target = get_target(argv[1], &target_size);

  printf("Searching on %d threads\nFor prefix ", cores);
  for(int i = 0; i < target_size/2; i++){
    printf("%02x", target[i]);
  }
  if(target_size % 2 == 1){
    printf("%x", (target[target_size/2 + 1] >> 4));
  }
  printf("\n");

  libkeccak_spec_sha3(&spec, 256);

  pthread_t threads[cores];
  unsigned long long counters[cores];

  for(int i = 0; i < cores; i++){
    counters[i] = 0;
    pthread_create(&threads[i], NULL, generate_address, &counters[i]);
  }

  clock_t timer = clock();
  unsigned long long hashes;


  while(!finished){
    if(clock() - timer >= 1000000){
      hashes = 0;
      for(int i = 0; i < cores; i++){
	hashes += counters[i];
	counters[i] = 0;
      }
      printf("KH/s: %llu\n", hashes/1000);
      timer = clock();
    }
  }
  for(int i = 0; i < cores; i++){
    pthread_join(threads[i], NULL);
  }

  free(target);
}
