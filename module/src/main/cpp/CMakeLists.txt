cmake_minimum_required(VERSION 3.22...3.31)
project(cleverestricky)




if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(DEBUG_BUILD)
    add_compile_options(-O0 -g)
else()
    # Obfuscation / Size Optimization flags
add_compile_options(-fvisibility=hidden -fvisibility-inlines-hidden -Os -flto)
add_link_options(-s -Wl,--gc-sections -Wl,--exclude-libs,ALL)
endif()

# We still want GC sections everywhere to reduce size, but don't strip symbols in debug
add_link_options(-Wl,--gc-sections)

# Treat all warnings as errors for C/C++
add_compile_options(-Werror -Wall -Wextra -Wno-unused-parameter -fno-rtti)


add_library(elf_util STATIC elf_util/elf_util.cpp)
add_library(my_logging STATIC logging/logging.cpp)

add_subdirectory(external)

target_include_directories(my_logging PUBLIC logging/include)
target_include_directories(elf_util PUBLIC elf_util/include)

target_link_libraries(my_logging log)
target_link_libraries(elf_util lsplt my_logging)

# libutils stub
add_library(utils SHARED binder/stub_utils.cpp)
target_include_directories(utils PUBLIC binder/include)

# libbinder stub
add_library(binder SHARED binder/stub_binder.cpp)
target_include_directories(binder PUBLIC binder/include)
target_link_libraries(binder PRIVATE utils)

add_executable(inject inject/main.cpp inject/utils.cpp)
target_link_libraries(inject PRIVATE lsplt my_logging)

# Rust Core Integration
add_library(rust_core STATIC IMPORTED)
set_target_properties(rust_core PROPERTIES IMPORTED_LOCATION
    ${CMAKE_CURRENT_SOURCE_DIR}/external/rust_libs/${ANDROID_ABI}/libcleverestricky_cbor_cose.a
)

add_library(${MODULE_NAME} SHARED binder_interceptor.cpp)
target_include_directories(${MODULE_NAME} PRIVATE ../../../../rust/cbor-cose/include)
target_link_libraries(${MODULE_NAME} PRIVATE log binder utils elf_util my_logging rust_core)

# Native Daemon for Race Condition Engine
add_executable(keystore_race_daemon daemon/main.cpp)
target_include_directories(keystore_race_daemon PRIVATE ../../../../rust/cbor-cose/include)
# Link against the same Rust core library
# Added my_logging to link dependencies to provide logging.hpp include path
target_link_libraries(keystore_race_daemon PRIVATE log binder utils rust_core my_logging)
set_target_properties(binder PROPERTIES LINK_FLAGS "-Wl,--allow-shlib-undefined")
set_target_properties(keystore_race_daemon PROPERTIES LINK_FLAGS "-Wl,--allow-shlib-undefined")
set_target_properties(cleverestricky PROPERTIES LINK_FLAGS "-Wl,--allow-shlib-undefined")
