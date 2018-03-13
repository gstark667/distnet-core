#include "keypair.h"
#include <string.h>


char hex_conv[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

std::string to_hex(uint8_t *data, size_t length)
{
    std::string output;
    for (size_t i = 0; i < length; ++i)
    {
        output += hex_conv[data[i] >> 4];
        output += hex_conv[data[i] & 15];
    }
    return output;
}

uint8_t hex_to_int(char value)
{
    if (value == '0')
        return 0;
    if (value == '1')
        return 1;
    if (value == '2')
        return 2;
    if (value == '3')
        return 3;
    if (value == '4')
        return 4;
    if (value == '5')
        return 5;
    if (value == '6')
        return 6;
    if (value == '7')
        return 7;
    if (value == '8')
        return 8;
    if (value == '9')
        return 9;
    if (value == 'A')
        return 10;
    if (value == 'B')
        return 11;
    if (value == 'C')
        return 12;
    if (value == 'D')
        return 13;
    if (value == 'E')
        return 14;
    if (value == 'F')
        return 15;
    return 0;
}

uint8_t *from_hex(std::string hex)
{
    uint8_t *data = (uint8_t*)malloc(sizeof(uint8_t) * hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        uint8_t value = hex_to_int(hex.at(i)) << 4;
        value |= hex_to_int(hex.at(i + 1));
        data[i/2] = value;
    }
    return data;
}

void keypair_load(keypair_t *keypair, std::string public_key, std::string secret_key)
{
    keypair->public_key = public_key;
    keypair->secret_key = secret_key;
}

void keypair_create(keypair_t *keypair)
{
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(public_key, secret_key);

    keypair->public_key = to_hex(public_key, crypto_box_PUBLICKEYBYTES);
    keypair->secret_key = to_hex(secret_key, crypto_box_SECRETKEYBYTES);
}

std::string make_nonce()
{
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(unsigned char) * crypto_box_NONCEBYTES);
    return to_hex(nonce, crypto_box_NONCEBYTES);
}

ciphertext_t keypair_encrypt(keypair_t *from, keypair_t *to, std::string message)
{
    ciphertext_t output;
    output.nonce = make_nonce();
    uint8_t *nonce_buf = from_hex(output.nonce);
    uint8_t *ciphertext = (uint8_t*)malloc(sizeof(uint8_t) * (crypto_box_MACBYTES + message.size()));
    uint8_t *public_key = from_hex(to->public_key);
    uint8_t *secret_key = from_hex(from->secret_key);
    if (crypto_box_easy(ciphertext, (unsigned char*)message.c_str(), message.size(), nonce_buf, public_key, secret_key) != 0)
    {
        free(nonce_buf);
        free(ciphertext);
        free(public_key);
        free(secret_key);
        return output;
    }
    output.body = to_hex(ciphertext, crypto_box_MACBYTES + message.size());
    free(nonce_buf);
    free(ciphertext);
    free(public_key);
    free(secret_key);
    return output;
}

plaintext_t keypair_decrypt(keypair_t *from, keypair_t *to, ciphertext_t ciphertext)
{
    plaintext_t output;
    uint8_t *ciphertext_buf = from_hex(ciphertext.body);
    uint8_t *nonce_buf = from_hex(ciphertext.nonce);
    uint8_t *plaintext = (uint8_t*)malloc(sizeof(uint8_t) * (ciphertext.body.size()/2 - crypto_box_MACBYTES + 1));
    memset((void*)plaintext, 0, (ciphertext.body.size()/2 - crypto_box_MACBYTES + 1));
    uint8_t *public_key = from_hex(from->public_key);
    uint8_t *secret_key = from_hex(to->secret_key);
    if (crypto_box_open_easy(plaintext, (unsigned char*)ciphertext_buf, ciphertext.body.size() / 2, nonce_buf, public_key, secret_key) != 0)
    {
        free(nonce_buf);
        free(plaintext);
        free(public_key);
        free(secret_key);
        return output;
    }
    output.body = std::string((char*)plaintext);
    output.nonce = ciphertext.nonce;
    free(nonce_buf);
    free(plaintext);
    free(public_key);
    free(secret_key);
    return output;
}

/*int main()
{
    keypair_t alice, bob;
    keypair_create(&alice);
    keypair_create(&bob);

    std::cout << alice.public_key << std::endl;
    std::cout << alice.secret_key << std::endl;

    std::cout << bob.public_key << std::endl;
    std::cout << bob.secret_key << std::endl;

    ciphertext_t encrypted = keypair_encrypt(&alice, &bob, "Hello world!");
    std::cout << encrypted.body << std::endl;

    plaintext_t decrypted = keypair_decrypt(&alice, &bob, encrypted);
    std::cout << decrypted.body << std::endl;
}*/

