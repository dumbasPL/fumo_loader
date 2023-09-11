add_library(fumo_loader STATIC fumo_loader.cpp driver_interface.cpp)
target_include_directories(fumo_loader PRIVATE ${CMAKE_SOURCE_DIR}/Include)
target_include_directories(fumo_loader PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_features(fumo_loader PUBLIC c_std_17 cxx_std_20)