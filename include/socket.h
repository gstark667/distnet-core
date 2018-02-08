#ifndef H_SOCKET
#define H_SOCKET

#include <string>
#include <vector>


struct address_t
{
    std::string protocol;
    std::string host;
    int port = 0;
};

struct message_t
{
    address_t address;
    std::string message;
};

struct socket_t
{
    int fd = -1;
    bool server = false;
    address_t address;
    std::vector<socket_t> clients;
};

address_t parse_uri(std::string uri);
std::string make_uri(address_t address);

bool sock_pair(socket_t *sock1, socket_t *sock2);

bool sock_bind(socket_t *sock, std::string uri);

bool sock_connect(socket_t *sock, std::string uri);

bool sock_can_handle(socket_t *sock, std::string uri);

bool sock_send_msg(socket_t *sock, message_t message);

message_t sock_recv_msg(socket_t *sock);

std::vector<socket_t*> sock_select(std::vector<socket_t*> socks);

bool sock_close(socket_t *sock);

bool operator==(const address_t &a, const address_t &b);
bool operator!=(const address_t &a, const address_t &b);
bool operator<(const address_t &a, const address_t &b);
bool operator>(const address_t &a, const address_t &b);

#endif
