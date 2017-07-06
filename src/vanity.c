#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libkeccak.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/random.h>

#define STEP 3072
#include "src/libsecp256k1-config.h"
#include "src/secp256k1.c"


#define ascii_to_byte(chr) (chr % 32 + 9) % 25

int finished = 0;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
unsigned long counter = 0;
clock_t timer;

unsigned char *target;
int target_size;

libkeccak_spec_t spec;


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

void *generate_address(void * param){

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

  int i = 0;
  do {
    secp256k1_ec_privkey_tweak_add(ctx, prv, tweak);
    secp256k1_ec_pubkey_tweak_add(ctx, &pub, tweak);
    secp256k1_ec_pubkey_serialize(ctx, public_key, &publen, &pub, SECP256K1_EC_UNCOMPRESSED);

    libkeccak_state_reset(state);
    libkeccak_fast_update(state, public_key+1, 64);
    libkeccak_fast_digest(state, NULL, 0, 0, NULL, address);

    if(i >= 100 && pthread_mutex_trylock(&lock) == 0){
      counter+=i;
      pthread_mutex_unlock(&lock);
      i = 0;
    }
    i++;
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

  for(int i = 0; i < cores; i++){
    pthread_create(&threads[i], NULL, generate_address, NULL);
  }

  while(!finished){
    if((clock() - timer) % 500000 == 0){
      printf("KH/s: %d\n", (counter * 1000)/(clock()-timer));
    }
  }
  for(int i = 0; i < cores; i++){
    pthread_join(threads[i], NULL);
  }

  free(target);
  pthread_mutex_destroy(&lock);
}
