cmake_minimum_required(VERSION 3.15 FATAL_ERROR)
project(fumo_loader)

include(cmake/CPM.cmake)

CPMAddPackage("gh:SergiusTheBest/FindWDK#master")
list(APPEND CMAKE_MODULE_PATH "${FindWDK_SOURCE_DIR}/cmake")
find_package(WDK REQUIRED)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(driver)
add_subdirectory(client)
