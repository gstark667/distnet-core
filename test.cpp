// https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html

#include <sodium.h>
#include <iostream>
#include <string.h>

#define MESSAGE (const unsigned char *) "test"
#define MESSAGE_LEN 4
#define CIPHERTEXT_LEN (crypto_box_MACBYTES + MESSAGE_LEN)

struct keypair_t
{
    uint8_t *public_key;
    uint8_t *secret_key;
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
    keypair->public_key = from_hex(public_key);
    keypair->secret_key = from_hex(secret_key);
}

void keypair_create(keypair_t *keypair)
{
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(public_key, secret_key);

    keypair->public_key = (uint8_t*)malloc(sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
    memcpy(keypair->public_key, public_key, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);

    keypair->secret_key = (uint8_t*)malloc(sizeof(uint8_t) * crypto_box_SECRETKEYBYTES);
    memcpy(keypair->secret_key, secret_key, sizeof(uint8_t) * crypto_box_SECRETKEYBYTES);
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
    if (crypto_box_easy(ciphertext, (unsigned char*)message.c_str(), message.size(), nonce_buf, to->public_key, from->secret_key) != 0)
    {
        free(nonce_buf);
        free(ciphertext);
        return output;
    }
    output.body = to_hex(ciphertext, crypto_box_MACBYTES + message.size());
    free(nonce_buf);
    free(ciphertext);
    return output;
}

std::string keypair_decrypt(keypair_t *from, keypair_t *to, ciphertext_t ciphertext)
{

}

void keypair_free(keypair_t *keypair)
{
    free(keypair->public_key);
    free(keypair->secret_key);
}

int main()
{
    unsigned char *alice_publickey = from_hex("4F67878F1675C2A98A437D7B0825B690522118AFFEC2A3E5A43722D8A40AA840");
    unsigned char *alice_secretkey = from_hex("794DBFB73F67D532CCF6D89366B32AF3B48EDB72FFB315B60C3B92EDF97E5D18");

    std::cout << to_hex(alice_publickey, crypto_box_PUBLICKEYBYTES) << std::endl;
    std::cout << to_hex(alice_secretkey, crypto_box_SECRETKEYBYTES) << std::endl;

    unsigned char bob_publickey[crypto_box_PUBLICKEYBYTES];
    unsigned char bob_secretkey[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(bob_publickey, bob_secretkey);

    std::cout << to_hex(bob_publickey, crypto_box_PUBLICKEYBYTES) << std::endl;
    std::cout << to_hex(bob_secretkey, crypto_box_SECRETKEYBYTES) << std::endl;

    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char ciphertext[CIPHERTEXT_LEN];
    randombytes_buf(nonce, sizeof nonce);
    if (crypto_box_easy(ciphertext, MESSAGE, MESSAGE_LEN, nonce, bob_publickey, alice_secretkey) != 0) {
        /* error */
        std::cout << "couldn't encrypt" << std::endl;
    }

    std::cout << to_hex(ciphertext, CIPHERTEXT_LEN) << std::endl;

    unsigned char decrypted[CIPHERTEXT_LEN] = "";
    uint8_t *data = from_hex(to_hex(ciphertext, CIPHERTEXT_LEN));
    //if (crypto_box_open_easy(decrypted, ciphertext, CIPHERTEXT_LEN, nonce, alice_publickey, bob_secretkey) != 0) {
    if (crypto_box_open_easy(decrypted, ciphertext, CIPHERTEXT_LEN, nonce, alice_publickey, bob_secretkey) != 0) {
        /* message for Bob pretending to be from Alice has been forged! */
        std::cout << "alice is a fake!" << std::endl;
    }
    free(data);
    std::cout << (char*)decrypted << std::endl;
}

