#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/random.h>
#include <sys/time.h>
#include "src/libsecp256k1-config.h"
#include "src/secp256k1.c"
#include "libkeccak.h"
#include "vanity.h"

int finished = 0;

unsigned char *target;
int target_size;

libkeccak_spec_t spec;

secp256k1_context *ctx;


int main(int argc, char* argv[]){

  int i;
  setbuf(stdout, NULL);

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

  printf("Searching on %d threads\nFor prefix ", cores);

  ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

  target = get_target(argv[1], &target_size);

  libkeccak_spec_sha3(&spec, 256);

  pthread_t threads[cores];
  unsigned long long counters[cores];

  for(i = 0; i < cores; i++){
    counters[i] = 0;
    pthread_create(&threads[i], NULL, generate_address, &counters[i]);
  }

  struct timespec start, end;
  clock_gettime(CLOCK_MONOTONIC_RAW, &start);

  unsigned long long hashes = 0;

  i = 0;
  while(!finished) {
    usleep(500000);
    for(int j = 0; j < cores; j++){
      hashes += counters[j];
      counters[j] = 0;
    }
    clock_gettime(CLOCK_MONOTONIC_RAW, &end);

    printf("\r                     \rKH/s: %llu", hashes/milisecond_diff(end, start));
    for(int j = 0; j < i % 6; j++){
      printf(".");
    }
    i++;
  }

  for(i = 0; i < cores; i++){
    pthread_join(threads[i], NULL);
  }

  printf("\nTotal addresses tried: %llu\n", hashes);

  free(target);
  secp256k1_context_destroy(ctx);
}

void *generate_address(void *ptr){

  unsigned long long *counter = ((unsigned long long *) ptr);
  libkeccak_state_t *state = libkeccak_state_create(&spec);

  unsigned char address[32];
  unsigned char public_key[65];
  size_t publen = 65;

  secp256k1_pubkey pub;
  unsigned char prv[32];
  getrandom(prv, 32, 0);
  secp256k1_ec_pubkey_create(ctx, &pub, prv);
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
  libkeccak_state_fast_free(state);
}


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

  for(int i = 0; i < len/2; i++){
    printf("%02x", buffer[i]);
  }
  if(target_size % 2 == 1){
    printf("%x", (buffer[len/2] >> 4));
  }
  printf("\n");

  return buffer;
}
