#include "node.h"

#include <iostream>
#include <sstream>

using namespace std;


bool parse_request(message_t message, request_t *output)
{
    size_t colon_pos = message.message.find(":");
    string trailer = "";
    string args = "";
    if (colon_pos != string::npos)
    {
        trailer = message.message.substr(colon_pos + 1, message.message.size());
        args = message.message.substr(0, colon_pos);
    }
    else
    {
        args = message.message;
    }

    istringstream ss(args);
    try
    {
        for (size_t i = 0; ss; ++i)
        {
            string temp;
            ss >> temp; 
            if (temp.size() == 0)
                break;
            if (i == 0)
                output->nonce = stoi(temp);
            else if (i == 1)
                output->command = temp;
            else
                output->args.push_back(temp);
        }
    }
    catch (...)
    {
        return false;
    }

    if (colon_pos != string::npos)
        output->args.push_back(trailer);

    output->sender = message.address;
    return true;
}

message_t build_request_msg(request_t *request)
{
    message_t message;
    message.address = request->sender;
    message.message = to_string(request->nonce) + " " + request->command;
    for (size_t i = 0; i < request->args.size(); ++i)
    {
        if (i == request->args.size() - 1)
            message.message += ":";
        else
            message.message += " ";
        message.message += request->args.at(i);
    }
    return message;
}

bool node_handle_set_identity(node_t *node, request_t request)
{
    if (request.args.size() != 1 || request.sender.host != "")
        return false;

    keypair_load(&(node->identity), request.args.at(0), request.args.at(1));
    for (map<string, string>::iterator it = node->peers.begin(); it != node->peers.end(); ++it)
    {
        request_t new_request;
        new_request.command = "register";
        new_request.nonce = node->current_nonce++;
        if (parse_uri(it->second) == request.sender)
            continue;
        new_request.sender = parse_uri(it->second);
        new_request.args.push_back(request.args.at(0));
        node_send_request(node, new_request);
        node->waiting_requests[new_request.sender][new_request.nonce] = new_request;
    }

    return true;
}

bool node_handle_add_interface(node_t *node, request_t request)
{
    if (request.args.size() != 1 || request.sender.host != "")
        return false;

    socket_t new_sock;
    if (!sock_bind(&new_sock, request.args.at(0)))
    {
        cout << "could not bind" << endl;
        return false;
    }
    node->interfaces.push_back(new_sock);
    return true;
}

bool node_handle_remove_interface(node_t *node, request_t request)
{
    if (request.args.size() != 1 || request.sender.host != "")
        return false;

    vector<socket_t> to_remove;
    for (vector<socket_t>::iterator it = node->interfaces.begin(); it != node->interfaces.end(); ++it)
    {
        if (sock_close(&(*it), request.args.at(0)))
        {
            to_remove.push_back(*it);
        }
    }

    for (vector<socket_t>::iterator it = to_remove.begin(); it != to_remove.end(); ++it)
    {
        for (vector<socket_t>::iterator it2 = node->interfaces.begin(); it2 != node->interfaces.end(); ++it2)
        {
            if (it->address == it2->address)
            {
                node->interfaces.erase(it2);
                break;
            }
        }
    }

    if (node->interface_cb)
        node->interface_cb(request.args.at(0), false);
    return true;
}

bool node_handle_add_peer(node_t *node, request_t request)
{
    cout << "peering" << endl;
    socket_t *sock = NULL;
    for (vector<socket_t>::iterator it = node->interfaces.begin(); it != node->interfaces.end(); ++it)
    {
        if (sock_can_handle(&(*it), request.args.at(0)))
        {
            if (!sock_connect(&(*it), request.args.at(0)))
            {
                continue;
            }
            sock = &(*it);
            break;
        }
    }

    if (!sock)
    {
        cout << "making a new interface" << endl;
        socket_t new_sock;
        if (!sock_connect(&new_sock, request.args.at(0)))
        {
            return false;
        }

        if (node->interface_cb)
        {
            node->interface_cb(make_uri(new_sock.address), true);
        }
        node->interfaces.push_back(new_sock);
        sock = &(node->interfaces.back());
    }

    cout << "registering" << endl;
    request_t new_request;
    new_request.sender = parse_uri(request.args.at(0));
    new_request.nonce = node->current_nonce++;
    new_request.command = "register";
    new_request.args.push_back(node->identity.public_key);
    cout << "sending register: " << sock_send_msg(sock, build_request_msg(&new_request)) << endl;

    node->waiting_requests[new_request.sender][new_request.nonce] = new_request;

    return true;
}

bool node_handle_register(node_t *node, request_t request)
{
    cout << "handling register: " << request.args.size() << endl;
    if (request.args.size() != 1)
        return false;

    node->peers[request.args.at(0)] = make_uri(request.sender);
    cout << "registered " << request.args.at(0) << ":" << node->peers[request.args.at(0)] << endl;

    request_t new_request;
    new_request.sender = request.sender;
    new_request.nonce = request.nonce;
    new_request.command = "reply";
    new_request.args.push_back(node->identity.public_key);

    return node_send_request(node, new_request);
}

bool node_handle_register_reply(node_t *node, request_t request, request_t reply)
{
    if (reply.args.size() != 1)
        return false;

    cout << "registering through reply: " << reply.args.at(0) << endl;
    node->peers[reply.args.at(0)] = make_uri(reply.sender);
    return true;
}

bool node_handle_discover(node_t *node, request_t request)
{
    cout << "handling discover" << endl;
    request_t reply;
    reply.sender = request.sender;
    reply.nonce = request.nonce;
    reply.command = "reply";
    cout << "do I know them?" << endl;
    // we know them directly
    if (node->identity.public_key == request.args.at(0) || node->peers.find(request.args.at(0)) != node->peers.end() || node->routes.find(request.args.at(0)) != node->routes.end())
    {
        cout << "I already know a route" << endl;
        reply.args.push_back("success");
        if (node_send_request(node, reply))
            return true;
    }

    cout << "am I doing it already?" << endl;
    if (node->discoveries.find(request.args.at(0)) != node->discoveries.end())
    {
        node->discoveries[request.args.at(0)].insert(request);
        return true;
    }
    else
    {
        node->discoveries[request.args.at(0)].insert(request);
    }

    // make a new request for everybody that can callback the reply
    request_t new_request;
    new_request.nonce = node->current_nonce++;
    new_request.command = "discover";
    new_request.args.push_back(request.args.at(0));
    new_request.callbacks[reply.sender].push_back(reply.nonce);

    cout << "asking everyone: " << node->peers.size() << endl;
    size_t requests_sent = 0;
    // send it to everybody
    for (map<string, string>::iterator it = node->peers.begin(); it != node->peers.end(); ++it)
    {
        cout << "can I ask this one? " << make_uri(request.sender) << endl;
        if (parse_uri(it->second) == request.sender)
            continue;
        new_request.sender = parse_uri(it->second);
        cout << "asking " << it->second << " if they know a route to " << new_request.args.at(0) << endl;
        node_send_request(node, new_request);
        node->waiting_requests[new_request.sender][new_request.nonce] = new_request;
        ++requests_sent;
    }

    // we can't ask anybody
    if (requests_sent == 0)
    {
        cout << "I couldn't ask anyone" << endl;
        reply.args.push_back("failure");
        if (node_send_request(node, reply))
            return true;
        return false;
    }
    
    // this reply needs to wait for us to discover the route
    node->waiting_requests[reply.sender][reply.nonce] = reply;
    node->discoveries[request.args.at(0)].insert(reply);
    return true;
}

bool node_handle_discover_reply(node_t *node, request_t request, request_t reply)
{
    cout << "discover reply" << endl;
    // we don't know about this discovery any more
    if (node->discoveries.find(request.args.at(0)) == node->discoveries.end())
    {
        return true;
    }
    // see if it's a failure
    if (reply.args.size() < 1 || reply.args.at(0) != "success")
    {
        if (node->discoveries.find(request.args.at(0)) != node->discoveries.end())
        {
            set<request_t>::iterator req = node->discoveries[request.args.at(0)].find(request);
            if (req != node->discoveries[request.args.at(0)].end())
                node->discoveries[request.args.at(0)].erase(req);
            // clean up the map if we were the last
            if (node->discoveries[request.args.at(0)].size() == 0)
                node->discoveries.erase(request.args.at(0));
        }
        return true;
    }
    // save the route
    node->routes[request.args.at(0)] = make_uri(reply.sender);
    cout << "can get to " << request.args.at(0) << " through " << make_uri(reply.sender) << endl;
    // tell everyone we succeeded
    request_t new_request;
    new_request.nonce = node->current_nonce++;
    new_request.command = "reply";
    new_request.args.push_back("success");
    new_request.callbacks[reply.sender].push_back(reply.nonce);
    for (set<request_t>::iterator it = node->discoveries[request.args.at(0)].begin(); it != node->discoveries[request.args.at(0)].end(); ++it)
    {
        new_request.sender = it->sender;
        new_request.nonce = it->nonce;
        node_send_request(node, new_request);
    }
    return true;
}

bool node_handle_send_msg(node_t *node, request_t request)
{
    cout << "handling send" << endl;
    if (request.args.size() != 4)
        return false;

    cout << "can I send to self?" << endl;
    if (request.args.at(0) == node->identity.public_key)
    {
        if (node->recv_cb)
        {
            keypair_t from;
            keypair_load(&from, request.args.at(1), "");
            ciphertext_t ciphertext;
            ciphertext.nonce = request.args.at(2);
            ciphertext.body = request.args.at(3);
            plaintext_t plaintext = keypair_decrypt(&from, &(node->identity), ciphertext);
            if (plaintext.body == "")
                return true;
            node->recv_cb(request.args.at(1), plaintext.body);
        }
        return true;
    }

    request_t new_request;
    new_request.nonce = node->current_nonce++;
    new_request.command = "send_msg";
    new_request.args.push_back(request.args.at(0));
    new_request.args.push_back(request.args.at(1));
    new_request.args.push_back(request.args.at(2));
    new_request.args.push_back(request.args.at(3));

    cout << "can I send to peer?" << endl;
    if (node->peers.find(request.args.at(0)) != node->peers.end())
    {
        new_request.sender = parse_uri(node->peers[request.args.at(0)]);
        if (node_send_request(node, new_request))
            return true;
    }

    cout << "do I know a route?" << endl;
    if (node->routes.find(request.args.at(0)) != node->routes.end())
    {
        new_request.sender = parse_uri(node->routes[request.args.at(0)]);
        if (node_send_request(node, new_request))
            return true;
    }

    cout << "cannot contact the other identity" << endl;

    return false;
}

bool node_handle_reply(node_t *node, request_t request)
{
    cout << "got reply" << endl;
    if (node->waiting_requests.find(request.sender) != node->waiting_requests.end())
    {
        if (node->waiting_requests[request.sender].find(request.nonce) != node->waiting_requests[request.sender].end())
        {
            // handle the reply
            cout << "handling reply for " << request.nonce << endl;
            if (node->reply_handlers.find(node->waiting_requests[request.sender][request.nonce].command) != node->reply_handlers.end())
                node->reply_handlers[node->waiting_requests[request.sender][request.nonce].command](node, node->waiting_requests[request.sender][request.nonce], request);

            // deal with any callbacks for the original request
            for (map<address_t, vector<int>>::iterator cbit = node->waiting_requests[request.sender][request.nonce].callbacks.begin(); cbit != node->waiting_requests[request.sender][request.nonce].callbacks.end(); ++cbit)
            {
                for (vector<int>::iterator cbit2 = cbit->second.begin(); cbit2 != cbit->second.end(); ++cbit2)
                {
                    // make sure that it still exists
                    if (node->waiting_requests.find(cbit->first) != node->waiting_requests.end() && node->waiting_requests[cbit->first].find(*cbit2) != node->waiting_requests[cbit->first].end())
                    {
                        std::cout << "doing callback" << std::endl;
                        node_send_request(node, node->waiting_requests[cbit->first][*cbit2]);
                    }
                }
            }

            // we're done with the request, so throw it away
            node->waiting_requests[request.sender].erase(request.nonce);
        }

        // clean up the map if this address doesn't have anything pending
        if (node->waiting_requests[request.sender].size() == 0)
        {
            node->waiting_requests.erase(request.sender);
        }
    }
    return true;
}

bool node_handle_stop(node_t *node, request_t request)
{
    if (request.args.size() != 0 || request.sender.host != "")
        return false;
    node->running = false;
    return true;
}

void node_start(node_t *node, string public_key, string secret_key, void (*recv_cb)(string, string), void (*interface_cb)(string, bool))
{
    socket_t control_receiver;
    sock_pair(&control_receiver, &(node->control_sock));
    node->interfaces.push_back(control_receiver);
    node->recv_cb = recv_cb;
    node->interface_cb = interface_cb;
    keypair_load(&(node->identity), public_key, secret_key);
    node->handlers["set_identity"] = &node_handle_set_identity;
    node->handlers["add_interface"] = &node_handle_add_interface;
    node->handlers["remove_interface"] = &node_handle_remove_interface;
    node->handlers["add_peer"] = &node_handle_add_peer;
    node->handlers["discover"] = &node_handle_discover;
    node->handlers["send_msg"] = &node_handle_send_msg;
    node->handlers["register"] = &node_handle_register;
    node->handlers["reply"] = &node_handle_reply;
    node->handlers["stop"] = &node_handle_stop;

    node->reply_handlers["register"] = &node_handle_register_reply;
    node->reply_handlers["discover"] = &node_handle_discover_reply;
    node->running = true;
}

void node_run(node_t *node)
{
    while (node->running)
    {
        vector<socket_t *> pre_select_socks, selected_socks;
        for (vector<socket_t>::iterator it = node->interfaces.begin(); it != node->interfaces.end(); ++it)
        {
            pre_select_socks.push_back(&(*it));
        }

        selected_socks = sock_select(pre_select_socks);
        for (vector<socket_t *>::iterator it = selected_socks.begin(); it != selected_socks.end(); ++it)
        {
            message_t message = sock_recv_msg(*it);
            request_t request;
            if (!parse_request(message, &request))
            {
                continue;
            }

            cout << "got message: " << message.message << endl;
            cout << "got command: " << request.command << endl;
            if (node->handlers.find(request.command) != node->handlers.end())
                node->handlers[request.command](node, request);
        }
    }
}

bool node_send_request(node_t *node, request_t request)
{
    for (vector<socket_t>::iterator it = node->interfaces.begin(); it != node->interfaces.end(); ++it)
    {
        if (sock_can_handle(&(*it), make_uri(request.sender)))
        {
            if (sock_send_msg(&(*it), build_request_msg(&request)))
            {
                return true;
            }
        }
    }
    return false;
}

void node_send(node_t *node, message_t message)
{
    sock_send_msg(&node->control_sock, message);
}

void node_set_identity(node_t *node, string public_key, string secret_key)
{
    request_t request;
    request.nonce = node->current_nonce++;
    request.command = "set_identity";
    request.args.push_back(public_key);
    request.args.push_back(secret_key);
    node_send(node, build_request_msg(&request));
}

void node_add_interface(node_t *node, string uri)
{
    request_t request;
    request.nonce = node->current_nonce++;
    request.command = "add_interface";
    request.args.push_back(uri);
    node_send(node, build_request_msg(&request));
}

void node_remove_interface(node_t *node, string uri)
{
    request_t request;
    request.nonce = node->current_nonce++;
    request.command = "remove_interface";
    request.args.push_back(uri);
    node_send(node, build_request_msg(&request));
}

void node_add_peer(node_t *node, string uri)
{
    request_t request;
    request.nonce = node->current_nonce++;
    request.command = "add_peer";
    request.args.push_back(uri);
    node_send(node, build_request_msg(&request));
}

void node_discover(node_t *node, string identity)
{
    request_t request;
    request.nonce = node->current_nonce++;
    request.command = "discover";
    request.args.push_back(identity);
    node_send(node, build_request_msg(&request));
}

void node_send_msg(node_t *node, string identity, string message)
{
    request_t request;
    keypair_t to;
    keypair_load(&to, identity, "");
    ciphertext_t ciphertext = keypair_encrypt(&(node->identity), &to, message);
    if (ciphertext.body == "")
        return;
    request.nonce = node->current_nonce++;
    request.command = "send_msg";
    request.args.push_back(identity);
    request.args.push_back(node->identity.public_key);
    request.args.push_back(ciphertext.nonce);
    request.args.push_back(ciphertext.body);
    node_send(node, build_request_msg(&request));
}

void node_stop(node_t *node)
{
    request_t request;
    request.nonce = node->current_nonce++;
    request.command = "stop";
    node_send(node, build_request_msg(&request));
}

bool operator==(const request_t &a, const request_t &b)
{
    return a.sender == b.sender && a.nonce == b.nonce;
}

bool operator!=(const request_t &a, const request_t &b)
{
    return a.sender != b.sender || a.nonce != b.nonce;
}

bool operator<(const request_t &a, const request_t &b)
{
    return make_uri(a.sender) + " " + to_string(a.nonce) < make_uri(b.sender) + " " + to_string(b.nonce);
}

bool operator>(const request_t &a, const request_t &b)
{
    return make_uri(a.sender) + " " + to_string(a.nonce) > make_uri(b.sender) + " " + to_string(b.nonce);
}

