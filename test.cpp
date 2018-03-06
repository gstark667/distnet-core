#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string>

#include <sodium.h>

struct keypair_t
{
    char* name;
    std::string public_key; //[crypto_box_PUBLICKEYBYTES];
    std::string secret_key; //[crypto_box_SECRETKEYBYTES];
};

/*int randombytes(uint8_t buffer[], unsigned long long size)
{
    int fd;
    fd = open( "/dev/urandom", O_RDONLY );
    if( fd < 0 )
        return -1;

    int rc;
    if( (rc = read( fd, buffer, size )) >= 0 )
        close( fd );
}*/

/*char* to_hex( char hex[], const uint8_t bin[], size_t length )
{
    int i;
    uint8_t *p0 = (uint8_t *)bin;
    char *p1 = hex;

    for( i = 0; i < length; i++ )
    {
        snprintf( p1, 3, "%02x", *p0 );
        p0 += 1;
        p1 += 2;
    }

    return hex;
}*/

std::string to_hex(uint8_t *data, size_t length)
{
    for (size_t i = 0; i < length; ++i)
    {
        
    }
}

int is_zero( const uint8_t *data, int len )
{
    int i;
    int rc;

    rc = 0;
    for(i = 0; i < len; ++i) {
        rc |= data[i];
    }

    return rc;
}

void *new_user(keypair_t *keypair, char *name)
{
    keypair->name = name;
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t secret_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(public_key, secret_key);
}

#define MAX_MSG_SIZE 1400

int encrypt(uint8_t encrypted[], const uint8_t pk[], const uint8_t sk[], const uint8_t nonce[], const uint8_t plain[], int length)
{
    uint8_t temp_plain[MAX_MSG_SIZE];
    uint8_t temp_encrypted[MAX_MSG_SIZE];
    int rc;

    printf("encrypt\n", length);

    if(length + crypto_box_ZEROBYTES >= MAX_MSG_SIZE) {
        return -2;
    }

    memset(temp_plain, '\0', crypto_box_ZEROBYTES);
    memcpy(temp_plain + crypto_box_ZEROBYTES, plain, length);

    rc = crypto_box(temp_encrypted, temp_plain, crypto_box_ZEROBYTES + length, nonce, pk, sk);

    if( rc != 0 ) {
        return -1;
    }

    if( is_zero(temp_plain, crypto_box_BOXZEROBYTES) != 0 ) {
        return -3;
    }

    memcpy(encrypted, temp_encrypted + crypto_box_BOXZEROBYTES, crypto_box_ZEROBYTES + length);

    return crypto_box_ZEROBYTES + length - crypto_box_BOXZEROBYTES;
}

int decrypt(uint8_t plain[], const uint8_t pk[], const uint8_t sk[], const uint8_t nonce[], const uint8_t encrypted[], int length)
{
    uint8_t temp_encrypted[MAX_MSG_SIZE];
    uint8_t temp_plain[MAX_MSG_SIZE];
    int rc;

    printf("decrypt\n");

    if(length+crypto_box_BOXZEROBYTES >= MAX_MSG_SIZE) {
        return -2;
    }

    memset(temp_encrypted, '\0', crypto_box_BOXZEROBYTES);
    memcpy(temp_encrypted + crypto_box_BOXZEROBYTES, encrypted, length);

    rc = crypto_box_open(temp_plain, temp_encrypted, crypto_box_BOXZEROBYTES + length, nonce, pk, sk);

    if( rc != 0 ) {
        return -1;
    }

    if( is_zero(temp_plain, crypto_box_ZEROBYTES) != 0 ) {
        return -3;
    }

    memcpy(plain, temp_plain + crypto_box_ZEROBYTES, crypto_box_BOXZEROBYTES + length);

    return crypto_box_BOXZEROBYTES + length - crypto_box_ZEROBYTES;
}

void print_keypair(keypair_t *keypair)
{
    char phexbuf[2*crypto_box_PUBLICKEYBYTES+1];
    char shexbuf[2*crypto_box_SECRETKEYBYTES+1];

    printf("username: %s\n", keypair->name);
    printf("public key: %s\n", to_hex(phexbuf, keypair->public_key, crypto_box_PUBLICKEYBYTES ));
    printf("secret key: %s\n\n", to_hex(shexbuf, keypair->secret_key, crypto_box_SECRETKEYBYTES ));
}

int main( int argc, char **argv )
{
    char hexbuf[256];

    int rc;
    keypair_t bob, eve;
    new_user(&bob, "bob");
    new_user(&eve, "eve");
    char *msg = "Hello";

    uint8_t nonce[crypto_box_NONCEBYTES];
    randombytes(nonce, crypto_box_NONCEBYTES);

    print_keypair(&bob);
    print_keypair(&eve);

    printf("message: %s\n", msg);

    uint8_t encrypted[1000];
    rc = encrypt(encrypted, bob.public_key, eve.secret_key, nonce, msg, strlen(msg));
    if( rc < 0 ) {
        return 1;
    }
    printf("encrypted: %s\n", to_hex(hexbuf, encrypted, rc ));

    uint8_t decrypted[1000];
    rc = decrypt(decrypted, eve.public_key, bob.secret_key, nonce, encrypted, rc);
    if( rc < 0 ) {
        return 1;
    }

    decrypted[rc] = '\0';
    printf("decrypted: %s\n", decrypted);

    return 0;
}
