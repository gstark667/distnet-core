#include "node.h"

#include <iostream>
#include <thread>
#include <chrono>


void message_callback(std::string sender, std::string message)
{
    std::cout << "got message from " << sender << ": " << message << std::endl;
}

int main(int argc, char **argv)
{
    if (argc < 5)
    {
        std::cerr << "need an identity, 2 addresses and a receiver identity" << std::endl;
        return 1;
    }

    node_t node;
    node_start(&node, argv[1], &message_callback);

    std::thread node_thread(node_run, &node);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    node_add_interface(&node, argv[2]);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    node_add_peer(&node, argv[3]);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    node_discover(&node, argv[4]);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    node_send_msg(&node, argv[4], "hi other person");

    //node_stop(&node);

    node_thread.join();
    return 0;
}
