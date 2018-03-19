cmake_minimum_required(VERSION 3.9)

project(distnet_core)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -lsodium")

find_package(Threads)

include_directories(include/)

set(HEADERS
    include/socket.h
    include/node.h
    include/keypair.h
)

set(SOURCES
    src/main.cpp
    src/socket.cpp
    src/node.cpp
    src/keypair.cpp
)

#TODO make it a library
#add_library(distnet_core SHARED ${SOURCES} ${HEADERS})
add_executable(distnet-core ${SOURCES} ${HEADERS})
target_link_libraries (distnet-core ${CMAKE_THREAD_LIBS_INIT})
target_include_directories (distnet-core PUBLIC include/)

