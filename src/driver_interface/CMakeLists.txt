add_library(driver_interface STATIC driver_interface.cpp)
target_include_directories(driver_interface PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_include_directories(driver_interface PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(driver_interface PUBLIC c_std_17 cxx_std_20)