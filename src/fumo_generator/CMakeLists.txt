add_executable(fumo_generator fumo_generator.cpp)
target_compile_features(fumo_generator PUBLIC c_std_17 cxx_std_20)
target_compile_definitions(fumo_generator PRIVATE UNICODE _UNICODE)
target_include_directories(fumo_generator PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
