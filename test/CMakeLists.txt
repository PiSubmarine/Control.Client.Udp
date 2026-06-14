cmake_minimum_required(VERSION 3.20)

include(FetchContent)

project(${PISUBMARINE_MODULE_NAME}.Test LANGUAGES CXX)

set(${PISUBMARINE_MODULE_NAME}.Test.Sources
        "PiSubmarine/Control/Client/Udp/ClientTest.cpp")

enable_testing()

find_package(GTest)

add_executable(${PISUBMARINE_MODULE_NAME}.Test ${${PISUBMARINE_MODULE_NAME}.Test.Sources})
PiSubmarineInitTarget(${PISUBMARINE_MODULE_NAME}.Test)

target_link_libraries(${PISUBMARINE_MODULE_NAME}.Test PRIVATE ${PISUBMARINE_MODULE_NAME})
target_link_libraries(${PISUBMARINE_MODULE_NAME}.Test PRIVATE PiSubmarine.Control.Serialization.Api.Mock)
target_link_libraries(${PISUBMARINE_MODULE_NAME}.Test PRIVATE PiSubmarine.Lease.Api.Mock)
target_link_libraries(${PISUBMARINE_MODULE_NAME}.Test PRIVATE PiSubmarine.Security.Aead.Api.Mock)
target_link_libraries(${PISUBMARINE_MODULE_NAME}.Test PRIVATE PiSubmarine.Security.Nonce.Api.Mock)
target_link_libraries(${PISUBMARINE_MODULE_NAME}.Test PRIVATE PiSubmarine.Udp.Api.Mock)
target_link_libraries(${PISUBMARINE_MODULE_NAME}.Test PRIVATE GTest::gtest_main)
include(GoogleTest)
if(CMAKE_CROSSCOMPILING)
    gtest_add_tests(TARGET ${PISUBMARINE_MODULE_NAME}.Test)
else()
    gtest_discover_tests(${PISUBMARINE_MODULE_NAME}.Test)
endif()
