cmake_minimum_required(VERSION 3.24)
project(portscan_cpp CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)

if(WIN32)
    set(PLATFORM_SOURCE src/WinSocket.cpp)
    set(PLATFORM_LIBS ws2_32)
else()
    set(PLATFORM_SOURCE src/LinuxSocket.cpp)
    set(PLATFORM_LIBS "")
endif()

add_library(portscan_core STATIC
    src/Args.cpp
    src/Ports.cpp
    src/Scanner.cpp
    src/Report.cpp
    ${PLATFORM_SOURCE}
)
target_include_directories(portscan_core PUBLIC src)
target_link_libraries(portscan_core PUBLIC ${PLATFORM_LIBS} Threads::Threads)

if(MSVC)
    target_compile_options(portscan_core PUBLIC /W4 /WX /utf-8)
else()
    target_compile_options(portscan_core PUBLIC -Wall -Wextra -Wpedantic -Werror)
endif()

add_executable(portscan src/main.cpp)
target_link_libraries(portscan PRIVATE portscan_core)

enable_testing()

add_executable(test_ports tests/test_ports.cpp)
target_link_libraries(test_ports PRIVATE portscan_core)
add_test(NAME ports COMMAND test_ports)

add_executable(test_scan tests/test_scan.cpp)
target_link_libraries(test_scan PRIVATE portscan_core)
add_test(NAME scan COMMAND test_scan)

add_executable(test_report tests/test_report.cpp)
target_link_libraries(test_report PRIVATE portscan_core)
add_test(NAME report COMMAND test_report)
