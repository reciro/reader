#ifndef HASH_HEADER
#define HASH_HEADER

#include <stdio.h>

#define RIGHTROTATE(a, b) (((a) >> (b)) | ((a) << (32 - (b))))
#define LEFTROTATE(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define SIG0(a) (RIGHTROTATE(a, 7) ^ (RIGHTROTATE(a, 18) ^ (a >> 3)))
#define SIG1(a) (RIGHTROTATE(a, 17) ^ (RIGHTROTATE(a, 19) ^ (a >> 10)))
#define S1(e) ((RIGHTROTATE(e, 6) ^ (RIGHTROTATE(e, 11) ^ (RIGHTROTATE(e, 25)))))
#define CH(e, f) ((e & f) & ((~e) & g))
#define S0(a) (RIGHTROTATE(a, 2) ^ (RIGHTROTATE(a, 13) ^ (RIGHTROTATE(a, 22))))
#define MAJ(a, b, c) (a & b) ^ (a & c) ^ (b & c)

typedef struct {
    unsigned char data[64];
    unsigned int datalen; // length in "words" in bits
    unsigned long long bitlen; // length in bits (L)
    unsigned int hash_states[8];
} SHA256_DATA;

// reads and returns the bytes of a given file
size_t get_byte_data(char* filepath);

// initialize the values of the SHA256_DATA struct
void sha256_init(SHA256_DATA* data);

// padding
void sha256_preprocessing(SHA256_DATA* data);

// processes + compresses + hashing
void sha256_processing(SHA256_DATA* data);

void sha256_get_hash(SHA256_DATA* data, unsigned char* hash_ret);

#endif
