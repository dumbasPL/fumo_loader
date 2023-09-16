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

add_library(initial_loader STATIC initial_loader.cpp)
target_link_libraries(initial_loader PRIVATE lazy_importer xorstr)
target_compile_definitions(initial_loader PRIVATE UNICODE _UNICODE LAZY_IMPORTER_NO_CPP_FORWARD)
target_compile_features(initial_loader PUBLIC c_std_17 cxx_std_20)
# disable security checks, disable SDL checks
target_compile_options(initial_loader PRIVATE /O1 /GS- /sdl-)

add_custom_command(
    DEPENDS initial_loader
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/libs/
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libs/initial_loader.obj
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/extract_lib.bat $<TARGET_LINKER_FILE:initial_loader>
)

add_executable(shellcode_extractor shellcode_extractor.cpp)
target_compile_features(shellcode_extractor PUBLIC c_std_17 cxx_std_20)
target_compile_definitions(shellcode_extractor PRIVATE UNICODE _UNICODE)

add_custom_command(
    DEPENDS shellcode_extractor
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/libs/initial_loader.obj
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libs/initial_loader.bin
    COMMAND shellcode_extractor ${CMAKE_CURRENT_BINARY_DIR}/libs/initial_loader.obj initial_loader ${CMAKE_CURRENT_BINARY_DIR}/libs/initial_loader.bin
)

add_executable(pe_generator pe_generator.cpp)
target_compile_features(pe_generator PUBLIC c_std_17 cxx_std_20)
target_compile_definitions(pe_generator PRIVATE UNICODE _UNICODE)
target_link_libraries(pe_generator PRIVATE lazy_importer)

add_custom_command(
    DEPENDS pe_generator
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/libs/initial_loader.bin
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/fumo_loader.exe
    COMMAND pe_generator ${CMAKE_CURRENT_BINARY_DIR}/libs/initial_loader.bin ${CMAKE_CURRENT_BINARY_DIR}/fumo_loader.exe
)

add_custom_target(
    fumo_loader_pe ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/fumo_loader.exe
)