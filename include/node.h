#ifndef H_NODE
#define H_NODE

#include "socket.h"
#include "keypair.h"

#include <string>
#include <vector>
#include <map>
#include <set>


struct request_t
{
    address_t sender;
    unsigned int nonce;
    std::string command;
    std::vector<std::string> args;
    std::map<address_t, std::vector<int>> callbacks;
};

struct node_t
{
    socket_t control_sock;
    std::vector<socket_t> interfaces;
    std::vector<message_t> messages;
    bool running = false;
    void (*recv_cb)(std::string, std::string) = NULL;
    void (*interface_cb)(std::string uri, bool add) = NULL;
    unsigned int current_nonce = 0;
    keypair_t identity;
    std::map<std::string, std::string> routes;
    std::map<std::string, std::string> peers;
    std::map<std::string, bool (*)(node_t*, request_t)> handlers;
    std::map<std::string, bool (*)(node_t*, request_t, request_t)> reply_handlers;
    std::map<address_t, std::map<int, request_t>> waiting_requests;
    std::map<std::string, std::set<request_t>> discoveries;
};

bool parse_request(message_t message, request_t *output);
message_t build_request_msg(request_t *request);

void node_start(node_t *node, std::string public_key, std::string secret_key, void (*message_cb)(std::string, std::string), void (*interface_cb)(std::string, bool));

void node_run(node_t *node);

bool node_send_request(node_t *node, request_t request);

void node_set_identity(node_t *node, std::string public_key, std::string secret_key);
void node_add_interface(node_t *node, std::string uri);
void node_remove_interface(node_t *node, std::string uri);
void node_add_peer(node_t *node, std::string uri);
void node_discover(node_t *node, std::string identity);
void node_send_msg(node_t *node, std::string identity, std::string message);

void node_stop(node_t *node);

bool operator==(const request_t &a, const request_t &b);
bool operator!=(const request_t &a, const request_t &b);
bool operator<(const request_t &a, const request_t &b);
bool operator>(const request_t &a, const request_t &b);

#endif
