cmake_minimum_required(VERSION 3.15 FATAL_ERROR)
project(fumo_loader)

# multi-processor compilation
if(MSVC)
    include(ProcessorCount)
    ProcessorCount(PROCESSOR_COUNT)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP${PROCESSOR_COUNT}")
    set(CMAKE_VS_MSBUILD_COMMAND "${CMAKE_VS_MSBUILD_COMMAND} /p:CL_MPCount=${PROCESSOR_COUNT} /m")
endif()

include(cmake/CPM.cmake)

CPMAddPackage("gh:SergiusTheBest/FindWDK#master")
list(APPEND CMAKE_MODULE_PATH "${FindWDK_SOURCE_DIR}/cmake")
find_package(WDK REQUIRED)

CPMAddPackage("gh:dumbasPL/libKDU#main")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(shellcode_extractor)
add_subdirectory(driver)
add_subdirectory(loader)
add_subdirectory(client)
