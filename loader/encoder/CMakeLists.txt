add_executable(fumo_encoder fumo_encoder.cpp)
target_compile_features(fumo_encoder PUBLIC c_std_17 cxx_std_20)
target_compile_definitions(fumo_encoder PRIVATE UNICODE _UNICODE)
target_include_directories(fumo_encoder PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
