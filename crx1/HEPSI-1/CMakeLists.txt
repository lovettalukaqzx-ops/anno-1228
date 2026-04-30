cmake_minimum_required(VERSION 3.20)
project(PSI)

# 设置C++标准
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 设置编译优化标志
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -mpclmul")

# 默认构建类型为 Release
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
endif()

# 定义目标文件
add_library(functions psi.cc)

# 使用 file(GLOB ...) 自动查找extra目录下的所有.cpp文件
file(GLOB NEW_MODULE_SRC "${CMAKE_SOURCE_DIR}/extra/*.cpp")

# 将所有找到的.cpp文件添加到functions库中
target_sources(functions PRIVATE ${NEW_MODULE_SRC})

# 设置头文件目录
include_directories("${CMAKE_SOURCE_DIR}/../preLibrary/include")
include_directories("${CMAKE_SOURCE_DIR}/../preLibrary/include/SEAL-4.1")
include_directories("${CMAKE_SOURCE_DIR}/extra")

# 设置库目录
link_directories("${CMAKE_SOURCE_DIR}/../preLibrary/lib")

# 定义可执行文件并链接库
add_executable(PSI main.cc)
target_link_libraries(PSI functions 
                          ${CMAKE_SOURCE_DIR}/../preLibrary/lib/libcryptoTools.a
                          ${CMAKE_SOURCE_DIR}/../preLibrary/lib/libseal-4.1.a)
