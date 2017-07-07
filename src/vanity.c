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

#define UPDATE_INTERVAL 500000

int cores;

unsigned char *target;
int target_size;

libkeccak_spec_t spec;
secp256k1_context *ctx;

pthread_t *threads;
unsigned long long volatile *counters;

volatile unsigned int finished;
pthread_mutex_t finished_lock = PTHREAD_MUTEX_INITIALIZER;

void status_loop(){
  struct timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);
  
  unsigned int j;
  unsigned long long total_count;

  while(!finished) {
    usleep(UPDATE_INTERVAL);
    pthread_mutex_lock(&finished_lock);

    // This is a rough estimate of the total hashes computed so far.
    // We don't need to synchronize these counters since they are monotonic 
    // and read-only
    total_count = 0;
    for(int i = 0; i < cores; i++){
      total_count += counters[i];
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    // Clear the status line
    printf("\r\33[2K\r");
    printf("KH/s: %llu", total_count/milisecond_diff(end, start));
    fflush(stdout);

    for(int i = 0;  i < j % 6; i++){
      printf(".");
      fflush(stdout);
    }
    j++;
    pthread_mutex_unlock(&finished_lock);
  }
}

int main(int argc, char* argv[]){

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
  libkeccak_spec_sha3(&spec, 256);

  target = get_target(argv[1], &target_size);
  
  threads = malloc(sizeof(pthread_t)*cores);
  counters = calloc(cores, sizeof(unsigned long long));
  // Launch worker threads
  for(unsigned long i = 0; i < cores; i++)
    pthread_create(&threads[i], NULL, generate_address, (void*) i);
  
  // Blocks until suitable address is found
  status_loop();

  for(int i = 0; i < cores; i++)
    pthread_join(threads[i], NULL);

  free(target);
  free(threads);
  free((void *)counters);
  secp256k1_context_destroy(ctx);
}

/* Searches for a secp256k1 private key `n` such that `kecac256(nG)` 
 * has the desired prefix. The strategy is:
 * 
 * 1. Pick a random initial private key [n]
 * 2. Do a single scalar multiplication [nG] to get a public key
 * 3. Tweak the public key using the efficient endomorphism \lambda
 *  - \lambda^3 = 1 \mod n so we can do this 3 times
 * 4. Tweak the public key by a single group addition
 * 5. Repeat until a good pub/priv keypair is found
 */
void *generate_address(void *ptr){
  
  unsigned int thread_no = (unsigned long) ptr;
  libkeccak_state_t *state = libkeccak_state_create(&spec);

  unsigned char address[32];
  unsigned char public_key[65];
  size_t publen = 65;

  secp256k1_pubkey pub;
  unsigned char prv[32];
  getrandom(prv, 32, 0);
  secp256k1_ec_pubkey_create(ctx, &pub, prv);
  secp256k1_ge p;

  unsigned int i = 0;

  while(!finished){
    if(i == 0){
        // [n := n+1, P := P+G]
        secp256k1_ec_privkey_tweak_add(ctx, prv, tweak);
        secp256k1_ec_pubkey_tweak_add(ctx, &pub, tweak);
    } 
    else {
        // [n := \lambda n, P = \lambda P]
        secp256k1_pubkey_load(ctx, &p, &pub);
        secp256k1_ge_mul_lambda(&p, &p);
        secp256k1_pubkey_save(&pub, &p);
        secp256k1_ec_privkey_tweak_mul(ctx, prv, secp256k1_scalar_consts_lambda);
    }
    // Serialize and hash the public key
    secp256k1_ec_pubkey_serialize(ctx, public_key, &publen, &pub, SECP256K1_EC_UNCOMPRESSED);
    libkeccak_state_reset(state);
    libkeccak_fast_update(state, public_key+1, 64);
    libkeccak_fast_digest(state, NULL, 0, 0, NULL, address);
    
    i = (i + 1) % 3;
    counters[thread_no]++;
  } while(hexcmp(address+12, target, target_size) != 0 && !finished);
    
    pthread_mutex_lock(&finished_lock);
    if(!finished){
        finished = 1;
        print_keys(address, prv);
    }
    pthread_mutex_unlock(&finished_lock);
  
  libkeccak_state_fast_free(state);
}

// Convert hex target prefix into prefix bytes
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
