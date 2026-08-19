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

# Integrate maxcalls library from SAF-AVTTS
add_subdirectory("../SAF-AVTTS" "${CMAKE_CURRENT_BINARY_DIR}/maxcalls_build" EXCLUDE_FROM_ALL)

set(SOURCES
	test.cpp
	udp_tunnel/tunnel.cpp
	udp_tunnel/maxcalls_tunnel.cpp
	udp_tunnel/auto_setup.cpp
)

if(WIN32)
	list(APPEND SOURCES udp_tunnel/windows_tap.cpp)
else()
	list(APPEND SOURCES udp_tunnel/linux_tun.cpp)
endif()

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE 
	${Boost_INCLUDE_DIRS}
	"../SAF-AVTTS/include"
)

target_link_libraries(${PROJECT_NAME} PRIVATE
	stdc++exp
	Boost::system
	maxcalls
)

if(WIN32)
	target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32 iphlpapi bcrypt)
else()
	target_link_libraries(${PROJECT_NAME} PRIVATE pthread)
endif()

include(CTest)
if(BUILD_TESTING)
	add_executable(saf-lep-protocol-tests tests/protocol_tests.cpp)
	target_compile_features(saf-lep-protocol-tests PRIVATE cxx_std_23)
	add_test(NAME saf-lep-protocol-tests COMMAND saf-lep-protocol-tests)
endif()
