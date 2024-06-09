wdk_add_driver(fumo_drv WINVER 0x4A61 driver.c memory.c thread.c signature.c)
target_include_directories(fumo_drv PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
set_target_properties(fumo_drv PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

# FIXME: add a cmake option to enable debug mode
target_compile_definitions(fumo_drv PRIVATE -DNO_FUMO_DRIVER_DEBUG)