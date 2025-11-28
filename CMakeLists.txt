cmake_minimum_required(VERSION 3.20)
project(packet-analyzer)

add_executable(main
    src/main.cpp
    src/pcap_facade.cpp
    src/printer.cpp)

target_link_libraries(main pcap)
target_compile_features(main PRIVATE cxx_std_17)
target_compile_options(main PRIVATE -Wall -Wextra -Wconversion -Wsign-conversion -Wfloat-conversion -pedantic-errors)