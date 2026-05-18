cmake_minimum_required(VERSION 3.10)
project(opcua_dmz_gateway C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_path(OPEN62541_INCLUDE_DIR open62541/client.h)
find_library(OPEN62541_LIB open62541)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_library(CJSON_LIB cjson)

if(NOT OPEN62541_INCLUDE_DIR)
    message(FATAL_ERROR "open62541 headers not found")
endif()

if(NOT OPEN62541_LIB)
    message(FATAL_ERROR "open62541 library not found")
endif()

if(NOT CJSON_LIB)
    message(FATAL_ERROR "cJSON library not found")
endif()

include_directories(
    ${OPEN62541_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

add_executable(opcua_dmz_gateway
    src/main.c
    src/southbound_client.c
    src/whitelist.c
    src/cache.c
    src/northbound_server.c
    src/influx_writer.c
    src/gds_client.c
    src/dmz_telemetry.c
)

target_link_libraries(opcua_dmz_gateway
    ${OPEN62541_LIB}
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
    ${CJSON_LIB}
)
