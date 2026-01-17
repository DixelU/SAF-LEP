# CMakeLists.txt for SAF-LEP Android Native Library
#
# This file configures the native C++ build for Android using the NDK.
# It should be referenced from your Android Studio project's build.gradle:
#
#   android {
#       externalNativeBuild {
#           cmake {
#               path "src/main/cpp/CMakeLists.txt"
#               version "3.22.1"
#           }
#       }
#   }
#
# PREREQUISITES:
# 1. Boost compiled for Android (arm64-v8a, armeabi-v7a, x86_64)
#    Recommended tool: https://github.com/moritz-wundke/Boost-for-Android
# 2. Set BOOST_ROOT environment variable or edit paths below

cmake_minimum_required(VERSION 3.22.1)

project("saf-lep")

# C++ Standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable debugging symbols in Debug builds
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")

# ============================================================================
# Boost Configuration
# ============================================================================
# Option 1: Set via environment variable
# Option 2: Edit these paths to match your Boost installation

# Expected structure:
#   ${BOOST_ROOT}/
#   ├── include/
#   │   └── boost/
#   └── lib/
#       ├── arm64-v8a/
#       │   ├── libboost_system.a
#       │   └── libboost_thread.a
#       ├── armeabi-v7a/
#       │   └── ...
#       └── x86_64/
#           └── ...

if(DEFINED ENV{BOOST_ROOT})
    set(BOOST_ROOT $ENV{BOOST_ROOT})
else()
    # Default path - adjust as needed
    set(BOOST_ROOT ${CMAKE_SOURCE_DIR}/../libs/boost)
endif()

message(STATUS "BOOST_ROOT: ${BOOST_ROOT}")
message(STATUS "Android ABI: ${ANDROID_ABI}")

# Boost include directory
set(BOOST_INCLUDE_DIR ${BOOST_ROOT}/include)
if(NOT EXISTS ${BOOST_INCLUDE_DIR})
    message(WARNING "Boost include directory not found: ${BOOST_INCLUDE_DIR}")
    message(WARNING "Please compile Boost for Android and set BOOST_ROOT")
endif()

# Boost libraries for current ABI
set(BOOST_LIB_DIR ${BOOST_ROOT}/lib/${ANDROID_ABI})
if(NOT EXISTS ${BOOST_LIB_DIR})
    message(WARNING "Boost library directory not found: ${BOOST_LIB_DIR}")
endif()

# ============================================================================
# Source Files
# ============================================================================

# Path to core SAF-LEP source files (relative to this CMakeLists.txt)
set(CORE_SRC_DIR ${CMAKE_SOURCE_DIR}/../../)

set(SOURCES
    # JNI Bridge
    native-lib.cpp

    # Core tunnel implementation
    ${CORE_SRC_DIR}/udp_tunnel/tunnel.cpp

    # Android TUN adapter
    ${CORE_SRC_DIR}/udp_tunnel/android_tun.cpp
)

# ============================================================================
# Library Definition
# ============================================================================

add_library(saf-lep SHARED ${SOURCES})

# Include directories
target_include_directories(saf-lep PRIVATE
    ${BOOST_INCLUDE_DIR}
    ${CORE_SRC_DIR}
)

# ============================================================================
# Find Libraries
# ============================================================================

# Android log library (for __android_log_print)
find_library(log-lib log)

# ============================================================================
# Link Libraries
# ============================================================================

# Import Boost libraries as static libraries
if(EXISTS ${BOOST_LIB_DIR}/libboost_system.a)
    add_library(boost_system STATIC IMPORTED)
    set_target_properties(boost_system PROPERTIES
        IMPORTED_LOCATION ${BOOST_LIB_DIR}/libboost_system.a
    )
else()
    message(WARNING "libboost_system.a not found in ${BOOST_LIB_DIR}")
endif()

if(EXISTS ${BOOST_LIB_DIR}/libboost_thread.a)
    add_library(boost_thread STATIC IMPORTED)
    set_target_properties(boost_thread PROPERTIES
        IMPORTED_LOCATION ${BOOST_LIB_DIR}/libboost_thread.a
    )
endif()

target_link_libraries(saf-lep
    # Android system libraries
    ${log-lib}
    atomic

    # Boost (if found)
    $<TARGET_NAME_IF_EXISTS:boost_system>
    $<TARGET_NAME_IF_EXISTS:boost_thread>
)

# ============================================================================
# Compiler Flags
# ============================================================================

target_compile_options(saf-lep PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter  # Boost headers have unused parameters
)

# Define Android macro (should be auto-defined by NDK, but be explicit)
target_compile_definitions(saf-lep PRIVATE
    __ANDROID__
    BOOST_ASIO_NO_DEPRECATED
)

# ============================================================================
# Installation (for standalone builds outside Android Studio)
# ============================================================================

# Install the shared library
install(TARGETS saf-lep
    LIBRARY DESTINATION lib/${ANDROID_ABI}
)
