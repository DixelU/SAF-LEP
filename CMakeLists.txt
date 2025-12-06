cmake_minimum_required(VERSION 3.22)
project(SAF-LEP)

if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    set(Boost_ROOT "D:/Progs/mingw64")
    set(Boost_INCLUDE_DIR "D:/Progs/mingw64/include")
    set(Boost_LIBRARY_DIR "D:/Progs/mingw64/lib")
    set(Boost_USE_STATIC_LIBS ON)
    set(Boost_DEBUG ON)
endif()

find_package(Boost REQUIRED COMPONENTS system)

set(SOURCES
	test.cpp
	udp_tunnel/tunnel.cpp
)

if(WIN32)
    list(APPEND SOURCES udp_tunnel/windows_tap.cpp)
else()
    list(APPEND SOURCES udp_tunnel/linux_tun.cpp)
endif()

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE ${Boost_INCLUDE_DIRS})

target_link_libraries(${PROJECT_NAME} PRIVATE
	stdc++exp
	Boost::system
)

if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32 iphlpapi)
else()
    target_link_libraries(${PROJECT_NAME} PRIVATE pthread)
endif()