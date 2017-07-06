#define ascii_to_byte(chr) (chr % 32 + 9) % 25
#define milisecond_diff(t1, t2) ((t1.tv_sec - t2.tv_sec) * 1000 + (t1.tv_nsec - t2.tv_nsec) / 1000000)


const unsigned char secp256k1_scalar_consts_lambda[32] = {
  0x53,0x63,0xad,0x4c,0xc0,0x5c,0x30,0xe0,
  0xa5,0x26,0x1c,0x02,0x88,0x12,0x64,0x5a,
  0x12,0x2e,0x22,0xea,0x20,0x81,0x66,0x78,
  0xdf,0x02,0x96,0x7c,0x1b,0x23,0xbd,0x72
};

const unsigned char tweak[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};



unsigned char *get_target(char* hex, int *size);
void *generate_address(void *ptr);


int hexcmp(unsigned char *a, unsigned char *b, int hexlen){
  int c = memcmp(a, b, hexlen/2);
  if(c != 0 || hexlen % 2 == 0){
    return c;
  }
  else {
    return !(a[hexlen/2] >> 4 ==  b[hexlen/2] >> 4);
  }
}

void print_keys(unsigned char *address, unsigned char *privkey){
  int i = 0;
  printf("\nAddress: ");
  for(i = 12; i < 32; i++){
    printf("%02x", address[i]);
  }
  printf("\nPrivate Key: ");
  for(i = 0; i<32; i++){
    printf("%02x", privkey[i]);
  }
  printf("\n");
}
