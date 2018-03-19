#ifndef H_KEYPAIR
#define H_KEYPAIR

#include <sodium.h>
#include <iostream>


struct keypair_t
{
    std::string public_key;
    std::string secret_key;
};

struct ciphertext_t
{
    std::string body;
    std::string nonce;
};

struct plaintext_t
{
    std::string body;
    std::string nonce;
};


std::string to_hex(uint8_t *data, size_t length);
uint8_t hex_to_int(char value);
uint8_t *from_hex(std::string hex);

void keypair_load(keypair_t *keypair, std::string public_key, std::string secret_key);

void keypair_create(keypair_t *keypair);

std::string make_nonce();

ciphertext_t keypair_encrypt(keypair_t *from, keypair_t *to, std::string message);

plaintext_t keypair_decrypt(keypair_t *from, keypair_t *to, ciphertext_t ciphertext);

#endif
