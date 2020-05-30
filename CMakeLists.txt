cmake_minimum_required(VERSION 2.8)
project(dhcp C)

include(CompileOptions.cmake)

set(PLUGIN 0 CACHE BOOL "Build a plugin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

include_directories(${CMAKE_SOURCE_DIR}/src/)

set(SOURCES
    src/dhcp.c
    src/srpu.c
    src/srpo_ubus.c
    src/transform_data.c
    src/utils/memory.c
)

# git SHA1 hash
execute_process(
    COMMAND
    git describe --always --abbrev=40
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE
    GIT_SHA1
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE
)


# get sysrepo version
find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
    execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} "--modversion" "libsysrepo" OUTPUT_VARIABLE SYSREPO_VERSION)
    if(SYSREPO_VERSION)
        # strip new line from string
        string(STRIP ${SYSREPO_VERSION} SYSREPO_VERSION)
        if(${SYSREPO_VERSION} VERSION_LESS "1.0.0")
            message(FATAL_ERROR "${PROJECT_NAME} requires at least libsysrepo verision 1.0.0")
        endif()
    endif()
endif()

# generate version.h
configure_file("${PROJECT_SOURCE_DIR}/src/version.h.in" "${PROJECT_SOURCE_DIR}/src/version.h" ESCAPE_QUOTES @ONLY)

if(PLUGIN)
    add_library(${CMAKE_PROJECT_NAME} MODULE ${SOURCES})
    install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION lib)
else()
    add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
    install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION bin)
endif()

set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES OUTPUT_NAME ${CMAKE_PROJECT_NAME} PREFIX "")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules")
find_package(LibYANG REQUIRED)
find_package(SYSREPO REQUIRED)
find_package(UCI REQUIRED)
find_package(LIBUBOX REQUIRED)
find_package(LIBUBUS REQUIRED)
find_package(JSON-C REQUIRED)


target_link_libraries(
    ${PROJECT_NAME}
    ${LIBYANG_LIBRARIES}
    ${SYSREPO_LIBRARIES}
    ${UCI_LIBRARIES}
    ${LIBUBOX_LIBRARIES}
    ${LIBUBUS_LIBRARIES}
    ${JSON-C_LIBRARIES}
)

include_directories(
    ${LIBYANG_INCLUDE_DIRS}
    ${SYSREPO_INCLUDE_DIRS}
    ${UCI_INCLUDE_DIR}
    ${LIBUBOX_INCLUDE_DIR}
    ${LIBUBUS_INCLUDE_DIR}
    ${SR_UCI_INCLUDE_DIR}
    ${JSON-C_INCLUDE_DIR}
)
