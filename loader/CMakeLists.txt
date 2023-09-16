add_subdirectory(driver)
add_subdirectory(driver_interface)
add_subdirectory(rsource_generator)
add_subdirectory(stage1)
add_subdirectory(stage2)
add_subdirectory(initial_loader)
add_subdirectory(shellcode_extractor)
add_subdirectory(pe_generator)

add_custom_command(
    COMMENT "building final executable"
    DEPENDS pe_generator initial_loader stage1
        $<TARGET_PROPERTY:initial_loader,RUNTIME_OUTPUT_DIRECTORY>/initial_loader.bin
        $<TARGET_FILE:stage1>
    COMMAND pe_generator ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_CFG_INTDIR}/fumo.exe
        $<TARGET_PROPERTY:initial_loader,RUNTIME_OUTPUT_DIRECTORY>/initial_loader.bin
        $<TARGET_FILE:stage1>
    OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_CFG_INTDIR}/fumo.exe
)

add_custom_target(
    fumo ALL
    DEPENDS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_CFG_INTDIR}/fumo.exe
)