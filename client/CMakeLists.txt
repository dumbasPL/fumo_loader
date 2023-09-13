add_executable(fumo client.cpp util.cpp)

target_include_directories(fumo PRIVATE ${CMAKE_SOURCE_DIR}/Include)
target_link_libraries(fumo PUBLIC fumo_loader libKDU)
target_compile_features(fumo PUBLIC c_std_17 cxx_std_20)
target_compile_definitions(fumo PRIVATE UNICODE _UNICODE)