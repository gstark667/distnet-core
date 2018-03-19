#include "socket.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <iostream>


address_t parse_uri(std::string uri)
{
    address_t address;

    size_t slash_pos = uri.find("://");
    size_t port_pos = uri.rfind(":");

    address.protocol = uri.substr(0, slash_pos);
    address.host = uri.substr(slash_pos + 3, port_pos - slash_pos - 3);
    address.port = stoi(uri.substr(port_pos + 1, uri.size() - port_pos - 1));

    return address;
}

std::string make_uri(address_t address)
{
    return address.protocol + "://" + address.host + ":" + std::to_string(address.port);
}

bool sock_pair(socket_t *sock1, socket_t *sock2)
{
    int fds[2];
    if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fds) < 0)
        return false;

    socket_t new_sock1, new_sock2;
    new_sock1.fd = fds[0];
    new_sock2.fd = fds[1];
    sock1->address.protocol = "tcp";
    sock1->clients.push_back(new_sock1);
    sock2->address.protocol = "tcp";
    sock2->clients.push_back(new_sock2);
    return true;
}

bool sock_bind_tcp(socket_t *sock, address_t address)
{
    sock->address = address;
    sock->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock->fd < 0)
        return false;

    struct sockaddr_in sockaddr;
    sockaddr.sin_addr.s_addr = INADDR_ANY;
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(sock->address.port);

    if (bind(sock->fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0)
        return false;

    listen(sock->fd, 3);
    sock->server = true;

    return true;
}

bool sock_bind_udp(socket_t *sock, address_t address)
{
    sock->address = address;
    sock->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock->fd < 0)
        return false;

    struct sockaddr_in sockaddr;
    sockaddr.sin_addr.s_addr = INADDR_ANY;
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(sock->address.port);

    if (bind(sock->fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0)
        return false;

    sock->server = true;

    return true;
}

bool sock_bind(socket_t *sock, std::string uri)
{
    address_t address = parse_uri(uri);
    if (address.protocol == "tcp")
        return sock_bind_tcp(sock, address);
    else if (address.protocol == "udp")
        return sock_bind_udp(sock, address);
    return false;
}

bool sock_connect_tcp(socket_t *sock, address_t address)
{
    socket_t new_sock;
    sock->address.protocol = address.protocol;
    new_sock.address = address;
    new_sock.fd = socket(AF_INET, SOCK_STREAM, 0);
    if (new_sock.fd < 0)
    {
        return false;
    }

    struct sockaddr_in sockaddr;
    struct hostent *host_addr = gethostbyname(address.host.c_str());
    bcopy((char *)host_addr->h_addr, (char *)&sockaddr.sin_addr.s_addr, host_addr->h_length);
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(address.port);

    if (connect(new_sock.fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0)
    {
        return false;
    }

    sock->server = false;
    new_sock.server = false;
    sock->clients.push_back(new_sock);
    return true;
}

bool sock_connect_udp(socket_t *sock, address_t address)
{
    if (sock->fd != -1)
        return true;

    sock->address = address;

    sock->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock->fd < 0)
        return false;

    struct sockaddr_in sockaddr;
    struct hostent *host_addr = gethostbyname(sock->address.host.c_str());
    bcopy((char *)host_addr->h_addr, (char *)&sockaddr.sin_addr.s_addr, host_addr->h_length);
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(sock->address.port);

    if (connect(sock->fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0)
    {
        return false;
    }

    sock->server = false;
    return true;
}

bool sock_can_handle_tcp(socket_t *sock, address_t address)
{
    for (std::vector<socket_t>::iterator it = sock->clients.begin(); it != sock->clients.end(); ++it)
    {
        if (it->address == address)
            return true;
    }
    return false;
}

bool sock_can_handle_udp(socket_t *sock, address_t address)
{
    if (sock->address == address)
        return false;
    return true;
}

bool sock_can_handle(socket_t *sock, std::string uri)
{
    address_t address = parse_uri(uri);
    if (address.protocol != sock->address.protocol)
        return false;
    if (sock->address.protocol == "tcp")
        return sock_can_handle_tcp(sock, address);
    else if (sock->address.protocol == "udp")
        return sock_can_handle_udp(sock, address);
    return false;
}

bool sock_connect(socket_t *sock, std::string uri)
{
    address_t address = parse_uri(uri);
    if (address.protocol == "tcp")
        return sock_connect_tcp(sock, address);
    else if (address.protocol == "udp")
        return sock_bind_udp(sock, address);
    return false;
}

bool sock_send_tcp(socket_t *sock, message_t message)
{
    for (std::vector<socket_t>::iterator it = sock->clients.begin(); it != sock->clients.end(); ++it)
    {
        if (it->address != message.address)
            continue;
        if (send(it->fd, message.message.c_str(), message.message.size(), 0) != -1)
        {
            return true;
        }
    }
    return false;
}

bool sock_send_udp(socket_t *sock, message_t message)
{
    struct sockaddr_in sockaddr;
    struct hostent *host_addr = gethostbyname(message.address.host.c_str());
    bcopy((char *)host_addr->h_addr, (char *)&sockaddr.sin_addr.s_addr, host_addr->h_length);
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(message.address.port);
    if (sendto(sock->fd, message.message.c_str(), message.message.size(), 0, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) != -1)
        return true;
    return false;
}

bool sock_send_msg(socket_t *sock, message_t message)
{
    if (sock->address.protocol == "tcp")
        return sock_send_tcp(sock, message);
    else if (sock->address.protocol == "udp")
        return sock_send_udp(sock, message);
    return false;
}

message_t sock_recv_tcp(socket_t *sock)
{
    fd_set readset;
    FD_ZERO(&readset);
    int max_fd = -1;

    if (sock->server)
    {
        max_fd = sock->fd;
        FD_SET(sock->fd, &readset);
    }
        
    for (std::vector<socket_t>::iterator it = sock->clients.begin(); it != sock->clients.end(); ++it)
    {
        if (it->fd > max_fd)
            max_fd = it->fd;
        FD_SET(it->fd, &readset);
    }

    int result = select(max_fd + 1, &readset, NULL, NULL, NULL);

    if (sock->server && FD_ISSET(sock->fd, &readset))
    {
        struct sockaddr_in new_sockaddr;
        int c = sizeof(struct sockaddr_in);
        message_t message;
        message.address = sock->address;

        socket_t new_sock;
        new_sock.fd = accept(sock->fd, (struct sockaddr *)&new_sockaddr, (socklen_t*)&c);
        if (new_sock.fd < 0)
            return message;

        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &new_sockaddr.sin_addr, str, INET_ADDRSTRLEN);

        new_sock.address.protocol = sock->address.protocol;
        new_sock.address.host = std::string(str);
        new_sock.address.port = ntohs(new_sockaddr.sin_port);

        sock->clients.push_back(new_sock);
        return message;
    }

    for (std::vector<socket_t>::iterator it = sock->clients.begin(); it != sock->clients.end(); ++it)
    {
        if (!FD_ISSET(it->fd, &readset))
            continue;

        message_t message;
        ssize_t buf_size = 0;
        ioctl(it->fd, FIONREAD, &buf_size);

        if (buf_size == 0)
        {
            message.address = sock->address;
            message.message = "";
            sock->clients.erase(it);
            return message;
        }

        char *buf = (char *)malloc(sizeof(char) * buf_size + 1);
        bzero(buf, buf_size + 1);

        recv(it->fd, buf, buf_size, 0);

        message.message = std::string(buf);
        message.address = it->address;
        free(buf);

        return message;
    }
    message_t message;
    return message;
}

message_t sock_recv_udp(socket_t *sock)
{
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(sock->fd, &readset);
    int result = select(sock->fd + 1, &readset, NULL, NULL, NULL);

    struct sockaddr_in new_sockaddr;
    int c = sizeof(struct sockaddr_in);

    ssize_t buf_size = 0;
    ioctl(sock->fd, FIONREAD, &buf_size);

    char *buf = (char *)malloc(sizeof(char) * buf_size + 1);
    bzero(buf, buf_size + 1);

    recvfrom(sock->fd, buf, buf_size, 0, (struct sockaddr *)&new_sockaddr, (socklen_t*)&c);

    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &new_sockaddr.sin_addr, str, INET_ADDRSTRLEN );

    message_t message;
    message.address.protocol = sock->address.protocol;
    message.address.host = std::string(str);
    message.address.port = ntohs(new_sockaddr.sin_port);
    message.message = std::string(buf);
    free(buf);

    return message;
}

message_t sock_recv_msg(socket_t *sock)
{
    if (sock->address.protocol == "tcp")
        return sock_recv_tcp(sock);
    else if (sock->address.protocol == "udp")
        return sock_recv_udp(sock);
    message_t empty;
    return empty;
}

std::vector<socket_t*> sock_select(std::vector<socket_t*> socks)
{
    std::vector<socket_t*> return_socks;
    fd_set readset;
    FD_ZERO(&readset);
    int max_fd = -1;

    for (std::vector<socket_t*>::iterator it = socks.begin(); it != socks.end(); ++it)
    {
        if ((*it)->server)
        {
            FD_SET((*it)->fd, &readset);
            if ((*it)->fd > max_fd)
                max_fd = (*it)->fd;
        }
        for (std::vector<socket_t>::iterator it2 = (*it)->clients.begin(); it2 != (*it)->clients.end(); ++it2)
        {
            FD_SET(it2->fd, &readset);
            if (it2->fd > max_fd)
                max_fd = it2->fd;
        }
    }

    int result = select(max_fd + 1, &readset, NULL, NULL, NULL);
    for (std::vector<socket_t*>::iterator it = socks.begin(); it != socks.end(); ++it)
    {
        bool ready = false;
        if ((*it)->server && FD_ISSET((*it)->fd, &readset))
            ready = true;
        for (std::vector<socket_t>::iterator it2 = (*it)->clients.begin(); it2 != (*it)->clients.end(); ++it2)
            if (FD_ISSET(it2->fd, &readset))
                ready = true;
        if (ready)
            return_socks.push_back(*it);
    }

    return return_socks;
}

bool sock_close(socket_t * sock, std::string uri)
{
    address_t address = parse_uri(uri);
    bool close_all = address == sock->address;
    for (std::vector<socket_t>::iterator it = sock->clients.begin(); it != sock->clients.end(); ++it)
    {
        if (close_all || address == it->address)
        {
            close(it->fd);
        }
    }
    if (close_all)
    {
        close(sock->fd);
        return true;
    }
    return false;
}

bool operator==(const address_t &a, const address_t &b)
{
    return a.protocol == b.protocol && a.host == b.host && a.port == b.port;
}

bool operator!=(const address_t &a, const address_t &b)
{
    return a.protocol != b.protocol || a.host != b.host || a.port != b.port;
}

bool operator<(const address_t &a, const address_t &b)
{
    return make_uri(a) < make_uri(b);
}

bool operator>(const address_t &a, const address_t &b)
{
    return make_uri(a) > make_uri(b);
}

