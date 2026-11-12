cmake_minimum_required(VERSION 3.16)
project(client_server_fixture C)

add_executable(echo-server server.c)
add_executable(echo-client client.c)
