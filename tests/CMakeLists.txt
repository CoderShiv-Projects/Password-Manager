add_executable(ppm_tests
  test_main.cpp
  test_structures.cpp
  test_manager.cpp
  test_generator.cpp
  test_storage.cpp
  test_api.cpp)
target_link_libraries(ppm_tests PRIVATE ppm_core)
target_compile_definitions(ppm_tests PRIVATE PPM_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
add_test(NAME ppm_tests COMMAND ppm_tests)
