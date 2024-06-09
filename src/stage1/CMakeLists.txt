add_custom_command(
    DEPENDS resource_generator fumo_drv
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Resources/fumo_drv_data.cpp ${CMAKE_CURRENT_BINARY_DIR}/Resources/fumo_drv_data.h
    COMMAND resource_generator $<TARGET_FILE:fumo_drv> fumo_drv_data ${CMAKE_CURRENT_BINARY_DIR}/Resources
)

add_custom_command(
    DEPENDS resource_generator stage2
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Resources/stage2_data.cpp ${CMAKE_CURRENT_BINARY_DIR}/Resources/stage2_data.h
    COMMAND resource_generator $<TARGET_FILE:stage2> stage2_data ${CMAKE_CURRENT_BINARY_DIR}/Resources
)

set(STAGE1_RESOURCES
    ${CMAKE_CURRENT_BINARY_DIR}/Resources/fumo_drv_data.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/Resources/stage2_data.cpp
)

add_library(stage1 MODULE stage1.cpp anti_idiot.cpp fumo_preloader.cpp ${STAGE1_RESOURCES})
target_include_directories(stage1 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include ${CMAKE_CURRENT_BINARY_DIR}/Resources)
target_compile_features(stage1 PUBLIC c_std_17 cxx_std_20)
target_compile_definitions(stage1 PRIVATE UNICODE _UNICODE)
target_compile_options(stage1 PRIVATE /O1 /GS- /sdl- /guard:cf- /Zc:threadSafeInit-)
target_link_libraries(stage1 PUBLIC ntdll libKDU driver_interface lazy_importer)
set_target_properties(stage1 PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

if (FUMO_DRIVER_DEBUG)
    target_compile_definitions(stage1 PRIVATE -DFUMO_DRIVER_DEBUG)
endif()