wdk_add_driver(fumo_drv WINVER 0x4A61 driver.c memory.c thread.c)

target_include_directories(fumo_drv PRIVATE ${CMAKE_SOURCE_DIR}/Include)