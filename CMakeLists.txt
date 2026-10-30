cmake_minimum_required(VERSION 3.16)
project(PersonalPasswordManager VERSION 1.0.0 LANGUAGES CXX)

# C++17. Compiler extensions stay ON (gnu++17) because MinGW's headers expose
# some Windows/POSIX helpers (gmtime_s, sockets) only in that mode.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(PPM_BUILD_TESTS "Build the test executable" ON)
option(PPM_STATIC_LINK "Link statically (Windows/MSYS2: avoids missing-DLL errors)" OFF)

# --- Dependency check: libsodium (found through pkg-config) -----------------
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(SODIUM IMPORTED_TARGET libsodium)
endif()
if(NOT SODIUM_FOUND)
  message(FATAL_ERROR
    "libsodium was not found.\n"
    "  MSYS2 (MINGW64 shell): pacman -S mingw-w64-x86_64-libsodium mingw-w64-x86_64-pkgconf\n"
    "  Ubuntu/Debian:         sudo apt install libsodium-dev pkg-config\n"
    "  macOS (Homebrew):      brew install libsodium pkg-config")
endif()
find_package(Threads REQUIRED)

# cpp-httplib (third_party/httplib.h) and nlohmann/json (third_party/nlohmann/json.hpp)
# are vendored, so no installation is needed for them.
foreach(f third_party/httplib.h third_party/nlohmann/json.hpp)
  if(NOT EXISTS "${CMAKE_SOURCE_DIR}/${f}")
    message(FATAL_ERROR "Missing ${f}. See README.md, section 'Vendored dependencies'.")
  endif()
endforeach()

add_library(ppm_core STATIC
  backend/crypto_util.cpp
  backend/password_entry.cpp
  backend/linked_list.cpp
  backend/stack.cpp
  backend/password_manager.cpp
  backend/password_generator.cpp
  backend/storage.cpp
  backend/api.cpp)
target_include_directories(ppm_core PUBLIC backend third_party)
target_link_libraries(ppm_core PUBLIC PkgConfig::SODIUM Threads::Threads)
if(MSVC)
  target_compile_options(ppm_core PRIVATE /W4)
else()
  target_compile_options(ppm_core PRIVATE -Wall -Wextra)
endif()
if(WIN32)
  target_compile_definitions(ppm_core PUBLIC _WIN32_WINNT=0x0A00)   # required by cpp-httplib
  target_link_libraries(ppm_core PUBLIC ws2_32)
endif()
if(PPM_STATIC_LINK AND WIN32)
  target_compile_definitions(ppm_core PUBLIC SODIUM_STATIC)
  target_link_options(ppm_core PUBLIC -static)
endif()

add_executable(password_manager backend/main.cpp)
target_link_libraries(password_manager PRIVATE ppm_core)
target_compile_definitions(password_manager PRIVATE PPM_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

if(PPM_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
