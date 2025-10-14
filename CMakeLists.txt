cmake_minimum_required(VERSION 3.27 FATAL_ERROR)

project(ida-pro-mcp VERSION 1.0.0)

# C++ Standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

#=============================================================================
# IDA SDK Configuration
#=============================================================================

# Set IDA SDK path
set(IDASDK "$ENV{HOME}/CLionProjects/idaprosdk91" CACHE PATH "Path to IDA SDK")

if(NOT EXISTS "${IDASDK}")
    message(FATAL_ERROR "IDA SDK not found at: ${IDASDK}")
endif()

# Platform detection
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(__EA64__ 1)
    set(IDAPLATFORM "x64_linux_gcc_64")
else()
    set(IDAPLATFORM "x86_linux_gcc_32")
endif()

# IDA SDK include directories
set(IDA_INCLUDE_DIR "${IDASDK}/include")
set(IDA_LIB_DIR "${IDASDK}/lib/${IDAPLATFORM}")

# Check if ida-cmake exists
if(EXISTS "${IDASDK}/ida-cmake/idasdk.cmake")
    include("${IDASDK}/ida-cmake/idasdk.cmake")
    message(STATUS "Using ida-cmake from SDK")
else()
    message(WARNING "ida-cmake not found, using manual configuration")

    # Manual IDA SDK configuration
    set(IDA_LIBRARIES
            "${IDA_LIB_DIR}/libida.so"
            "${IDA_LIB_DIR}/pro.a"
    )

    # Platform definitions
    add_compile_definitions(
            __LINUX__=1
            __X64__=1
    )

    if(__EA64__)
        add_compile_definitions(__EA64__=1)
    endif()

    # Compiler flags to match IDA SDK
    add_compile_options(
            -fPIC
            -fno-strict-aliasing
            -Wno-deprecated
            -Wno-write-strings
    )
endif()

#=============================================================================
# cpp-httplib Configuration
#=============================================================================

include(FetchContent)

FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.18.3
)
FetchContent_MakeAvailable(httplib)

# nlohmann/json
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

# OpenSSL
find_package(OpenSSL REQUIRED)

#=============================================================================
# Plugin Configuration
#=============================================================================

# Plugin source files
set(PLUGIN_SOURCES
    src/main.cpp
    src/http/auth.cpp
    src/http/handlers.cpp
    src/http/server.cpp
    src/tools/database_info.cpp
    src/tools/list_functions.cpp
    src/tools/get_function_at.cpp
    src/tools/read_bytes.cpp
    src/tools/tool_registry.cpp
)

# Create plugin as shared library
add_library(${PROJECT_NAME} SHARED ${PLUGIN_SOURCES})

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
        ${IDA_INCLUDE_DIR}
        ${CMAKE_SOURCE_DIR}/include
)

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE
        ${IDA_LIBRARIES}
        httplib::httplib
        nlohmann_json::nlohmann_json
        OpenSSL::SSL
        OpenSSL::Crypto
        pthread
        dl
)

# Set output properties for IDA plugin
set_target_properties(${PROJECT_NAME} PROPERTIES
        PREFIX ""
        SUFFIX ".so"
        OUTPUT_NAME "ida_mcp_plugin"
)

# Plugin extension based on platform
if(__EA64__)
    set_target_properties(${PROJECT_NAME} PROPERTIES
            SUFFIX "64.so"
    )
endif()

#=============================================================================
# Installation
#=============================================================================

# Install to IDA plugins directory (optional)
if(DEFINED IDA_INSTALL_DIR)
    install(TARGETS ${PROJECT_NAME}
            LIBRARY DESTINATION "${IDA_INSTALL_DIR}/plugins"
    )
endif()

#=============================================================================
# Debug Information
#=============================================================================

message(STATUS "=== IDA MCP Plugin Configuration ===")
message(STATUS "IDA SDK: ${IDASDK}")
message(STATUS "IDA Platform: ${IDAPLATFORM}")
message(STATUS "IDA Include: ${IDA_INCLUDE_DIR}")
message(STATUS "IDA Libraries: ${IDA_LIB_DIR}")
message(STATUS "cpp-httplib: v0.18.3")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "====================================")
