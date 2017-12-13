cmake_minimum_required(VERSION 2.6)

project(sysrepo-plugin-dt-dhcp)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
set(PLUGIN 0 CACHE BOOL "Build a plugin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -Wall")

set(SOURCES
    src/dhcp.c
    src/uci.c
    src/parse.c)

if(PLUGIN)
    add_library(${CMAKE_PROJECT_NAME} MODULE ${SOURCES})
    install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION lib)
else()
    add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
    install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION bin)
endif()

set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES
    OUTPUT_NAME ${CMAKE_PROJECT_NAME}
    PREFIX "")

find_package(SYSREPO REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} ${SYSREPO_LIBRARIES})
include_directories(${SYSREPO_INCLUDE_DIRS})

# dependencies - uci
FIND_PACKAGE(UCI REQUIRED)
INCLUDE_DIRECTORIES(${UCI_INCLUDE_DIR})
TARGET_LINK_LIBRARIES(${CMAKE_PROJECT_NAME} ${UCI_LIBRARIES} ${CMAKE_DL_LIBS})
