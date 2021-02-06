cmake_minimum_required(VERSION 3.13)
project(ooz C CXX)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(OOZ_SOURCES
    bitknit.cpp
    bits_rev_table.h
    compr_entropy.cpp
    compr_entropy.h
    compr_kraken.cpp
    compr_kraken.h
    compr_leviathan.cpp
    compr_leviathan.h
    compr_match_finder.cpp
    compr_match_finder.h
    compr_mermaid.cpp
    compr_mermaid.h
    compr_multiarray.cpp
    compr_tans.cpp
    compr_util.h
    compress.cpp
    compress.h
    kraken.cpp
    log_lookup.h
    lzna.cpp
    match_hasher.h
    qsort.h
    targetver.h
)

add_executable(ooz ${OOZ_SOURCES})

add_library(libooz SHARED ${OOZ_SOURCES})

target_compile_definitions(libooz PUBLIC OOZ_DYNAMIC)
target_compile_definitions(libooz PRIVATE OOZ_BUILD_DLL)
