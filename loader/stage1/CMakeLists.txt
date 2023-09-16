CPMAddPackage("gh:dumbasPL/libKDU#main")

add_custom_command(
    DEPENDS resource_generator fumo_drv
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Resources/fumo_drv.cpp
    COMMAND resource_generator $<TARGET_FILE:fumo_drv> fumo_drv_data ${CMAKE_CURRENT_BINARY_DIR}/Resources
)

add_library(stage1 MODULE fumo_preloader.cpp ${CMAKE_CURRENT_BINARY_DIR}/Resources/fumo_drv_data.cpp)
target_include_directories(stage1 PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/Resources)
target_compile_features(stage1 PUBLIC c_std_17 cxx_std_20)
target_compile_definitions(stage1 PRIVATE UNICODE _UNICODE)
target_compile_options(stage1 PRIVATE /O1 /GS- /sdl- /guard:cf- /Zc:threadSafeInit-)
target_link_libraries(stage1 PUBLIC fumo_loader libKDU)
