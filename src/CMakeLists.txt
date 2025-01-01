# disable C4711, C5045, C4820 (caused by lz4)
if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4711 /wd5045 /wd4820")
endif()

CPMAddPackage(
    NAME lz4
    GITHUB_REPOSITORY lz4/lz4
    VERSION 1.10.0
    SOURCE_SUBDIR build/cmake
    OPTIONS
        "LZ4_BUILD_CLI OFF"
        "LZ4_BUILD_LEGACY_LZ4C OFF"
)
find_package(lz4 REQUIRED)

CPMAddPackage("gh:can1357/linux-pe#master")
find_package(linux-pe REQUIRED)

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    CPMAddPackage(
        NAME xorstr
        GITHUB_REPOSITORY JustasMasiulis/xorstr
        GIT_TAG master
        DOWNLOAD_ONLY True
    )

    if (xorstr_ADDED)
        add_library(xorstr INTERFACE)
        target_include_directories(xorstr INTERFACE ${xorstr_SOURCE_DIR}/include)
    endif()

    CPMAddPackage(
        NAME lazy_importer
        GITHUB_REPOSITORY JustasMasiulis/lazy_importer
        GIT_TAG master
        DOWNLOAD_ONLY True
    )

    if (lazy_importer_ADDED)
        add_library(lazy_importer INTERFACE)
        target_include_directories(lazy_importer INTERFACE ${lazy_importer_SOURCE_DIR}/include)
    endif()

    CPMAddPackage("gh:SergiusTheBest/FindWDK#master")
    list(APPEND CMAKE_MODULE_PATH "${FindWDK_SOURCE_DIR}/cmake")
    find_package(WDK REQUIRED)

    CPMAddPackage("gh:dumbasPL/libKDU@1.4.3")

    add_subdirectory(driver)
    add_subdirectory(driver_interface)
    add_subdirectory(resource_generator)
    add_subdirectory(stage1)
    add_subdirectory(stage2)
    add_subdirectory(initial_loader)
    add_subdirectory(shellcode_extractor)
endif()

add_subdirectory(fumo_generator)
add_subdirectory(encoder)

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_custom_command(
        COMMENT "building final executable"
        DEPENDS fumo_generator initial_loader stage1
            $<TARGET_PROPERTY:initial_loader,RUNTIME_OUTPUT_DIRECTORY>/initial_loader.bin
            $<TARGET_FILE:stage1>
        COMMAND fumo_generator ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_CFG_INTDIR}/fumo.exe
            $<TARGET_PROPERTY:initial_loader,RUNTIME_OUTPUT_DIRECTORY>/initial_loader.bin
            $<TARGET_FILE:stage1>
        OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_CFG_INTDIR}/fumo.exe
    )

    add_custom_target(
        fumo ALL
        DEPENDS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_CFG_INTDIR}/fumo.exe
    )
endif()
