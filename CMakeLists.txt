cmake_minimum_required(VERSION 3.15 FATAL_ERROR)
project(fumo_loader VERSION 0.3.0)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# multi-processor compilation
if(MSVC)
    include(ProcessorCount)
    ProcessorCount(PROCESSOR_COUNT)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP${PROCESSOR_COUNT}")
    set(CMAKE_VS_MSBUILD_COMMAND "${CMAKE_VS_MSBUILD_COMMAND} /p:CL_MPCount=${PROCESSOR_COUNT} /m")
endif()

set(CPM_SOURCE_CACHE "${CMAKE_SOURCE_DIR}/.cache/cpm")
include(cmake/CPM.cmake)

add_subdirectory(src)