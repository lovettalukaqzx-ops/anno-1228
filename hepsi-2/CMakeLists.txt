cmake_minimum_required(VERSION 3.20)
project(HEPSI)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -mpclmul -fcoroutines")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
endif()

set(PRELIB ${CMAKE_SOURCE_DIR}/../crx1/preLibrary)
set(LOCAL_BINFUSE_DIR ${CMAKE_SOURCE_DIR}/prelib/binfuse)
set(SHARED_BINFUSE_DIR ${CMAKE_SOURCE_DIR}/../hepsi-1/prelib/binfuse)

set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BINFUSE_TEST OFF CACHE BOOL "" FORCE)
set(BINFUSE_BENCH OFF CACHE BOOL "" FORCE)

if(EXISTS ${LOCAL_BINFUSE_DIR}/CMakeLists.txt)
  add_subdirectory(prelib/binfuse)
elseif(EXISTS ${SHARED_BINFUSE_DIR}/CMakeLists.txt)
  add_subdirectory(${SHARED_BINFUSE_DIR} ${CMAKE_BINARY_DIR}/binfuse)
else()
  message(FATAL_ERROR "binfuse not found. Expected ${LOCAL_BINFUSE_DIR} or ${SHARED_BINFUSE_DIR}.")
endif()

find_package(SEAL 4.1 REQUIRED
  PATHS ${PRELIB}/lib/cmake/SEAL-4.1 /usr/local/lib/cmake/SEAL-4.1)

add_library(functions psi.cc)

target_include_directories(functions PUBLIC
  ${PRELIB}/include
  ${CMAKE_SOURCE_DIR}
)

target_link_libraries(functions PUBLIC
  binfuse
  SEAL::seal
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

add_executable(PSI main.cc)

target_link_libraries(PSI
  functions
)

add_library(functions_v psi_v.cc)

target_include_directories(functions_v PUBLIC
  ${PRELIB}/include
  ${CMAKE_SOURCE_DIR}
)

target_link_libraries(functions_v PUBLIC functions binfuse SEAL::seal)

add_executable(PSI_v main_v.cc)

target_link_libraries(PSI_v
  functions_v
)

add_executable(PSI_bench_he bench_he.cc)

target_link_libraries(PSI_bench_he
  functions
)

add_executable(PSI_batch_stats batch_stats.cc)

target_link_libraries(PSI_batch_stats
  functions
)
