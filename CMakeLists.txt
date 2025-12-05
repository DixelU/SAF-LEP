cmake_minimum_required(VERSION 3.22)
project(SAF-LEP)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Boost
find_package(Boost REQUIRED COMPONENTS system)

add_executable(${PROJECT_NAME} 
    test.cpp
    udp_tunnel/tunnel.cpp
)

target_include_directories(${PROJECT_NAME} PRIVATE ${Boost_INCLUDE_DIRS})

target_link_libraries(${PROJECT_NAME} PRIVATE
        stdc++exp
        Boost::system
)