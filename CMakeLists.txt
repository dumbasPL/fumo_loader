cmake_minimum_required(VERSION 3.15 FATAL_ERROR)
project(fumo_loader)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# multi-processor compilation
if(MSVC)
    include(ProcessorCount)
    ProcessorCount(PROCESSOR_COUNT)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP${PROCESSOR_COUNT}")
    set(CMAKE_VS_MSBUILD_COMMAND "${CMAKE_VS_MSBUILD_COMMAND} /p:CL_MPCount=${PROCESSOR_COUNT} /m")
endif()

include(cmake/CPM.cmake)

add_subdirectory(shellcode)
add_subdirectory(driver)
add_subdirectory(loader)
add_subdirectory(client)
