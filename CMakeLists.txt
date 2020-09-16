cmake_minimum_required(VERSION 3.15)
project(sm2_sm3 C)

set(CMAKE_C_STANDARD 99)

include_directories(include)
aux_source_directory(src SM2_SRC)
add_executable(sm2_sm3 main.c ${SM2_SRC})

# Openssl
find_package(OPENSSL)
IF(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
    target_link_libraries(sm2_sm3 ${OPENSSL_LIBRARIES})
    message(STATUS "openssl library found")
ELSE(OPENSSL_FOUND)
    message(FATAL_ERROR ”openssl library not found”)
ENDIF(OPENSSL_FOUND)