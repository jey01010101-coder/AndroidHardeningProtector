cmake_minimum_required(VERSION 3.4.1)
project(decryptor)

set(CMAKE_CXX_STANDARD 11)

# Add source files
add_library(decryptor SHARED
    decryptor.c
    anti_debug.c
    signature_check.c
)

# Include directories
include_directories(${CMAKE_SOURCE_DIR})

# Link libraries
find_library(log-lib log)

target_link_libraries(decryptor
    ${log-lib}
    dl
)

# Compiler flags
target_compile_options(decryptor PRIVATE
    -Wall
    -Wextra
    -O2
    -fvisibility=hidden
    -fPIC
)

# Strip debug symbols in release
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET decryptor POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-unneeded $<TARGET_FILE:decryptor>
    )
endif()