add_library(initial_loader_lib STATIC initial_loader.cpp)
target_link_libraries(initial_loader_lib PRIVATE lazy_importer xorstr)
target_compile_definitions(initial_loader_lib PRIVATE UNICODE _UNICODE)
target_compile_features(initial_loader_lib PUBLIC c_std_17 cxx_std_20)
target_compile_options(initial_loader_lib PRIVATE /O1 /GS- /sdl-)
target_include_directories(initial_loader_lib PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)

add_custom_command(
    COMMENT "Extracting initial_loader_lib"
    DEPENDS initial_loader_lib
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/initial_loader.obj
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/extract_lib.bat $<TARGET_LINKER_FILE:initial_loader_lib>
)

add_custom_command(
    COMMENT "Extracting initial_loader"
    DEPENDS shellcode_extractor
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/initial_loader.obj
    OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_CFG_INTDIR}/initial_loader.bin
    COMMAND shellcode_extractor ${CMAKE_CURRENT_BINARY_DIR}/initial_loader.obj initial_loader ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_CFG_INTDIR}/initial_loader.bin
)

add_custom_target(
    initial_loader
    DEPENDS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_CFG_INTDIR}/initial_loader.bin
    COMMENT "Building initial_loader.bin"
)
set_target_properties(initial_loader PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_CFG_INTDIR})