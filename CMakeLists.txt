cmake_minimum_required(VERSION 3.10.2)
project(jvmtest)
set(CMAKE_CXX_STANDARD 14)

find_package(JNI REQUIRED)
include_directories(${JAVA_INCLUDE_PATH})
include_directories(${JAVA_INCLUDE_PATH2})

link_directories(.)
add_executable(jvmtest main.cpp)
