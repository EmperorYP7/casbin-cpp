add_executable(
  dummy_test
  dummy_test.cpp
  main.cpp
)
target_link_libraries(
  dummy_test
  gtest_main
)

include(GoogleTest)
gtest_discover_tests(dummy_test)
