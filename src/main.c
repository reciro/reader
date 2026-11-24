#include "hash.h"
#include <stdio.h>

int main()
{
    get_byte_data("./src/main.c");

    SHA256_DATA data;
    sha256_init(&data);
    sha256_preprocessing(&data);
    unsigned char hash[32];
    sha256_get_hash(&data, hash);

    printf("0x%02X\n", hash);

    return 0;
}
