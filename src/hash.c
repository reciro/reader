#include <assert.h>
#include <hash.h>
#include <stdint.h>
#include <string.h>

// Initialize hash values:
static unsigned int h0 = 0x6a09e667;
static unsigned int h1 = 0xbb67ae85;
static unsigned int h2 = 0x3c6ef372;
static unsigned int h3 = 0xa54ff53a;
static unsigned int h4 = 0x510e527f;
static unsigned int h5 = 0x9b05688c;
static unsigned int h6 = 0x1f83d9ab;
static unsigned int h7 = 0x5be0cd19;

// Initialize array of round constants : (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
static const unsigned int k[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

size_t get_byte_data(char* filepath)
{
    unsigned char buffer[64];
    size_t total_bytes = 0;
    size_t n = 0;

    /* Read bytes from a file until EOF or an error */
    FILE* file = fopen(filepath, "r");
    if (file == NULL)
        return SIZE_MAX;

    while ((n = fread(buffer, 1, sizeof buffer, file)) > 0) {
        total_bytes += n;
        // TODO - Get the raw bytes of the file and return it with the total_bytes
    }

    fclose(file);

    return total_bytes;
}

void sha256_init(SHA256_DATA* data)
{
    data->bitlen = 0;
    data->datalen = 0;
    data->hash_states[0] = h0;
    data->hash_states[1] = h1;
    data->hash_states[2] = h2;
    data->hash_states[3] = h3;
    data->hash_states[4] = h4;
    data->hash_states[5] = h5;
    data->hash_states[6] = h6;
    data->hash_states[7] = h7;
}

void sha256_preprocessing(SHA256_DATA* data)
{
    uint64_t orig_msg_bitlen = data->bitlen;

    unsigned int k = (512 - ((orig_msg_bitlen + 1 + 64) % 512)) % 512;

    assert(k >= 7 && k % 8 == 7);
    unsigned int zero_bytes = (k - 7) / 8;

    unsigned int i = data->datalen;

    // Append 1 bit
    data->data[i++] = 0x80;
    data->bitlen += 8;
    data->datalen += 1;

    // Pad the rest of the data with 0 bit
    while (zero_bytes-- > 0) {
        data->data[i++] = 0x00;
        data->bitlen += 8;
        data->datalen += 1;
    }

    // Append 64 bit integer original message length
    for (int j = 7; j >= 0; --j) {
        data->data[i++] = (unsigned char)(orig_msg_bitlen >> (j * 8));
        data->bitlen += 8;
        data->datalen += 1;
    }

    // data now contains a whole number of 512-bit blocks.
    assert(data->bitlen % 512 == 0);
    assert(data->datalen % 64 == 0);
};

void sha256_processing(SHA256_DATA* data)
{
    int bits = data->bitlen;

    while (bits -= 512 > 0) {
        unsigned char message_array[64];
        unsigned int i, j = 0;
        for (; i < 16; ++i, j += 4)
            message_array[i] = (data->data[j] << 24) | (data->data[j + 1] << 16) | (data->data[j + 2] << 8) | (data->data[j + 3]);

        for (; i < 64; i++) {
            message_array[i] = message_array[i - 15] + SIG0(message_array[i - 15]) + message_array[i - 7] + SIG1(message_array[i - 2]);
        }

        // Initialize working variables to current hash value:
        unsigned int a = h0;
        unsigned int b = h1;
        unsigned int c = h2;
        unsigned int d = h3;
        unsigned int e = h4;
        unsigned int f = h5;
        unsigned int g = h6;
        unsigned int h = h7;

        // Compression function main loop:
        for (i = 0; i < 64; i++) {
            unsigned int s1 = S1(e);
            unsigned int ch = CH(e, f);
            unsigned int temp1 = h + s1 + ch + k[i] + message_array[i];
            unsigned int s0 = S0(a);
            unsigned int maj = MAJ(a, b, c);
            unsigned int temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // Add the compressed chunk to the current hash value:
        data->hash_states[0] += a;
        data->hash_states[1] += b;
        data->hash_states[2] += c;
        data->hash_states[3] += d;
        data->hash_states[4] += e;
        data->hash_states[5] += f;
        data->hash_states[6] += g;
        data->hash_states[7] += h;
    }
}

void sha256_get_hash(SHA256_DATA* data, unsigned char* hash_ret)
{
    memcpy(data->hash_states, hash_ret, 32);
}
