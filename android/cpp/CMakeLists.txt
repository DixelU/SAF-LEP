cmake_minimum_required(VERSION 3.22.1)

project(saf-lep LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SAF_LEP_BOOST_ROOT "" CACHE PATH "Boost root or include directory")
option(SAF_LEP_FETCH_BOOST "Download pinned Boost headers when none are installed" ON)

if(NOT SAF_LEP_BOOST_ROOT AND DEFINED ENV{BOOST_ROOT})
    set(SAF_LEP_BOOST_ROOT "$ENV{BOOST_ROOT}")
endif()

if(SAF_LEP_BOOST_ROOT)
    find_path(
        SAF_LEP_BOOST_INCLUDE_DIR
        boost/asio.hpp
        HINTS "${SAF_LEP_BOOST_ROOT}" "${SAF_LEP_BOOST_ROOT}/include"
        NO_DEFAULT_PATH
        NO_CMAKE_FIND_ROOT_PATH
    )
else()
    find_path(SAF_LEP_BOOST_INCLUDE_DIR boost/asio.hpp)
endif()

if(NOT SAF_LEP_BOOST_INCLUDE_DIR AND SAF_LEP_FETCH_BOOST)
    include(FetchContent)
    set(FETCHCONTENT_BASE_DIR "${CMAKE_CURRENT_LIST_DIR}/../.deps" CACHE PATH "Shared Android dependencies")
    FetchContent_Declare(
        saf_lep_boost
        URL https://archives.boost.io/release/1.87.0/source/boost_1_87_0.tar.gz
        URL_HASH SHA256=f55c340aa49763b1925ccf02b2e83f35fdcf634c9d5164a2acb87540173c741d
    )
    FetchContent_GetProperties(saf_lep_boost)
    if(NOT saf_lep_boost_POPULATED)
        FetchContent_Populate(saf_lep_boost)
    endif()
    set(SAF_LEP_BOOST_INCLUDE_DIR "${saf_lep_boost_SOURCE_DIR}")
endif()

if(NOT EXISTS "${SAF_LEP_BOOST_INCLUDE_DIR}/boost/asio.hpp")
    message(FATAL_ERROR
        "Boost headers were not found. Set BOOST_ROOT or SAF_LEP_BOOST_ROOT, "
        "or configure with SAF_LEP_FETCH_BOOST=ON."
    )
endif()

set(SAF_LEP_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

add_library(
    saf-lep
    SHARED
    native-lib.cpp
    "${SAF_LEP_ROOT}/udp_tunnel/tunnel.cpp"
    "${SAF_LEP_ROOT}/udp_tunnel/android_tun.cpp"
)

target_include_directories(
    saf-lep
    PRIVATE
    "${SAF_LEP_BOOST_INCLUDE_DIR}"
    "${SAF_LEP_ROOT}"
)

target_compile_definitions(
    saf-lep
    PRIVATE
    BOOST_ASIO_NO_DEPRECATED
)

target_compile_options(
    saf-lep
    PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wno-unused-parameter
)

find_library(ANDROID_LOG_LIBRARY log REQUIRED)

target_link_libraries(
    saf-lep
    PRIVATE
    "${ANDROID_LOG_LIBRARY}"
    atomic
)
