cmake_minimum_required(VERSION 3.17)

project(memdrv)

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(WDK REQUIRED)

wdk_add_driver(${PROJECT_NAME} KMDF 1.15 WINVER 0x0602
    src/main.cpp
    src/util.cpp
    src/detour.cpp
    )

target_include_directories(${PROJECT_NAME} PRIVATE include phnt)