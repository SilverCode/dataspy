cmake_minimum_required(VERSION 3.15)
project(dataspy)

set(CMAKE_CXX_STANDARD 11)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)

add_executable(dataspy main.cpp main.h)
target_link_libraries(dataspy PkgConfig::PCAP ${CMAKE_THREAD_LIBS_INIT})