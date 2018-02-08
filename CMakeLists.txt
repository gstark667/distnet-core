cmake_minimum_required(VERSION 3.9)

project(distnet_core)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)

find_package (Threads)

include_directories(include/)

set(HEADERS
    include/socket.h
    include/node.h
)

set(SOURCES
    src/main.cpp
    src/socket.cpp
    src/node.cpp
)

#TODO make it a library
#add_library(distnet_core SHARED ${SOURCES} ${HEADERS})
add_executable(distnet_core ${SOURCES} ${HEADERS})
target_link_libraries (distnet_core ${CMAKE_THREAD_LIBS_INIT})
target_include_directories(distnet_core PUBLIC include/)

