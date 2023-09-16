
add_library(stage1 MODULE fumo_preloader.cpp)
target_compile_definitions(stage1 PRIVATE UNICODE _UNICODE)
target_compile_options(stage1 PRIVATE /O1 /GS- /sdl- /guard:cf- /Zc:threadSafeInit-)
target_link_options(stage1 PRIVATE /ENTRY:stage1_main)
