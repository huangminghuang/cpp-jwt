# CMakeLists files in this project can
# refer to the root source directory of the project as ${HELLO_SOURCE_DIR} and
# to the root binary directory of the project as ${HELLO_BINARY_DIR}.

cmake_minimum_required (VERSION 3.5.0)
project (cpp-jwt)

set(CMAKE_CXX_STANDARD 14)

find_program(CONAN_EXECUTABLE NAMES conan)
if (CONAN_EXECUTABLE)

  if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
    message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
    file(DOWNLOAD "https://github.com/conan-io/cmake-conan/raw/v0.13/conan.cmake"
                  "${CMAKE_BINARY_DIR}/conan.cmake")
  endif()

  include(${CMAKE_BINARY_DIR}/conan.cmake)

  conan_cmake_run(CONANFILE conanfile.txt
              BASIC_SETUP CMAKE_TARGETS NO_OUTPUT_DIRS
              BUILD missing)
  set(CPPJWT_TEST_DEPS ${CONAN_TARGETS})             
else()
  find_package(OpenSSL REQUIRED)
  find_package(GTest REQUIRED)
  set(CPPJWT_TEST_DEPS OpenSSL::SSL OpenSSL::Crypto GTest::GTest GTest::Main)
endif()

function(cpp_jwt_target name)
  add_executable(${name} ${ARGV})
  target_include_directories(${name} PUBLIC ${CMAKE_SOURCE_DIR}/include)
  target_link_libraries(${name} ${CPPJWT_TEST_DEPS})
  add_test(NAME ${name} COMMAND ./${name} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

  if (MSVC)
    target_compile_options(${name} PRIVATE "/W4")
    set_target_properties(${name} PROPERTIES LINK_FLAGS "/ignore:4099")
  else(MSVC)
    target_compile_options(${name} PRIVATE "-Wall")
  endif(MSVC)
endfunction()


enable_testing()

# Recurse into the "Hello" and "Demo" subdirectories. This does not actually
# cause another cmake executable to run. The same process will walk through
# the project's entire directory structure.
add_subdirectory (tests)
add_subdirectory (examples)
