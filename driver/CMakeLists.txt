wdk_add_driver(fumo_drv driver.c)

target_include_directories(fumo_drv PRIVATE ${CMAKE_SOURCE_DIR}/Include)