cmake_minimum_required(VERSION 3.7)
project(etherwake-nfqueue C)

set(CMAKE_C_STANDARD 99)

link_libraries(netfilter_queue)

add_executable(etherwake-nfqueue
        ether-wake.c
        nfqueue.c nfqueue.h)
