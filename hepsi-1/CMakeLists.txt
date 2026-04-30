cmake_minimum_required(VERSION 3.20)
project(HEPSI)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -mpclmul -fcoroutines")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
endif()

# preLibrary paths
set(PRELIB ${CMAKE_SOURCE_DIR}/../crx1/preLibrary)

# binfuse (header-only, brings in xor_singleheader + mio)
add_subdirectory(prelib/binfuse)

# SEAL (BFV homomorphic encryption)
find_package(SEAL 4.1 REQUIRED
  PATHS ${PRELIB}/lib/cmake/SEAL-4.1 /usr/local/lib/cmake/SEAL-4.1)

# PSI library
add_library(functions psi.cc)

target_include_directories(functions PUBLIC
  ${PRELIB}/include
)

target_link_libraries(functions PUBLIC binfuse SEAL::seal)

# Executable
add_executable(PSI main.cc)

target_link_libraries(PSI
  functions
  ${PRELIB}/lib/liblibOTe.a
  ${PRELIB}/lib/libcoproto.a
  ${PRELIB}/lib/libmacoro.a
  ${PRELIB}/lib/libcryptoTools.a
  ${PRELIB}/lib/libbitpolymul.a
  ${PRELIB}/lib/libsodium.a
  ${PRELIB}/lib/libgmssl.so
  ${PRELIB}/lib/libboost_system.a
  ${PRELIB}/lib/libboost_thread.a
  pthread
)

# Profile executable
add_executable(PSI_profile profile.cc)

target_link_libraries(PSI_profile
  functions
  ${PRELIB}/lib/liblibOTe.a
  ${PRELIB}/lib/libcoproto.a
  ${PRELIB}/lib/libmacoro.a
  ${PRELIB}/lib/libcryptoTools.a
  ${PRELIB}/lib/libbitpolymul.a
  ${PRELIB}/lib/libsodium.a
  ${PRELIB}/lib/libgmssl.so
  ${PRELIB}/lib/libboost_system.a
  ${PRELIB}/lib/libboost_thread.a
  pthread
)

# HE operation benchmark
add_executable(PSI_bench_he bench_he.cc)

target_link_libraries(PSI_bench_he
  functions
  ${PRELIB}/lib/liblibOTe.a
  ${PRELIB}/lib/libcoproto.a
  ${PRELIB}/lib/libmacoro.a
  ${PRELIB}/lib/libcryptoTools.a
  ${PRELIB}/lib/libbitpolymul.a
  ${PRELIB}/lib/libsodium.a
  ${PRELIB}/lib/libgmssl.so
  ${PRELIB}/lib/libboost_system.a
  ${PRELIB}/lib/libboost_thread.a
  pthread
)

# Batch statistics runner
add_executable(PSI_batch_stats batch_stats.cc)

target_link_libraries(PSI_batch_stats
  pthread
)
