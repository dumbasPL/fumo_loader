wdk_add_driver(fumo_drv WINVER 0x4A61 driver.c memory.c thread.c)
target_include_directories(fumo_drv PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_link_options(fumo_drv PRIVATE /NOCOFFGRPINFO /ENTRY:DriverEntry)
set_target_properties(fumo_drv PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

if (FUMO_DRIVER_DEBUG)
    target_compile_definitions(fumo_drv PRIVATE -DFUMO_DRIVER_DEBUG)
endif()