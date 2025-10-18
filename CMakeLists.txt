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

# Set IDA SDK path - platform dependent defaults
if(WIN32)
    set(IDASDK "C:/idasdk91" CACHE PATH "Path to IDA SDK")
else()
    set(IDASDK "$ENV{HOME}/CLionProjects/idaprosdk91" CACHE PATH "Path to IDA SDK")
endif()

if(NOT EXISTS "${IDASDK}")
    message(FATAL_ERROR "IDA SDK not found at: ${IDASDK}")
endif()

# Platform detection
if(WIN32)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(__EA64__ 1)
        set(IDAPLATFORM "x64_win_vc_64")
    else()
        set(IDAPLATFORM "x86_win_vc_32")
    endif()
else()
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(__EA64__ 1)
        set(IDAPLATFORM "x64_linux_gcc_64")
    else()
        set(IDAPLATFORM "x86_linux_gcc_32")
    endif()
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
    if(WIN32)
        set(IDA_LIBRARIES
                "${IDA_LIB_DIR}/ida.lib"
        )

        # Platform definitions
        add_compile_definitions(
                __NT__=1
                _CRT_SECURE_NO_WARNINGS=1
                USE_DANGEROUS_FUNCTIONS=1
        )

        if(__EA64__)
            add_compile_definitions(__EA64__=1)
        endif()

        # Windows-specific compiler flags (only for MSVC)
        if(MSVC)
            add_compile_options(
                    /W3
                    /wd4267
                    /wd4244
            )
        else()
            # MinGW cross-compile flags
            add_compile_options(
                    -Wno-deprecated-declarations
            )
        endif()
    else()
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
# For cross-compilation, you may need to specify OPENSSL_ROOT_DIR
find_package(OpenSSL REQUIRED)

# Cross-compilation message
if(CMAKE_CROSSCOMPILING)
    message(STATUS "Cross-compiling for ${CMAKE_SYSTEM_NAME}")
    if(NOT OPENSSL_FOUND)
        message(FATAL_ERROR "OpenSSL not found for cross-compilation target. "
                "Please install OpenSSL for MinGW or specify -DOPENSSL_ROOT_DIR=<path>")
    endif()
endif()

#=============================================================================
# Plugin Configuration
#=============================================================================

# Plugin source files
set(PLUGIN_SOURCES
    src/main.cpp
    src/http/auth.cpp
    src/http/handlers.cpp
    src/http/server.cpp
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
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE
            ${IDA_LIBRARIES}
            httplib::httplib
            nlohmann_json::nlohmann_json
            OpenSSL::SSL
            OpenSSL::Crypto
    )
else()
    target_link_libraries(${PROJECT_NAME} PRIVATE
            ${IDA_LIBRARIES}
            httplib::httplib
            nlohmann_json::nlohmann_json
            OpenSSL::SSL
            OpenSSL::Crypto
            pthread
            dl
    )
endif()

# Set output properties for IDA plugin
if(WIN32)
    set_target_properties(${PROJECT_NAME} PROPERTIES
            PREFIX ""
            OUTPUT_NAME "ida_mcp_plugin"
    )

    # Plugin extension based on platform
    if(__EA64__)
        set_target_properties(${PROJECT_NAME} PROPERTIES
                SUFFIX "64.dll"
        )
    else()
        set_target_properties(${PROJECT_NAME} PROPERTIES
                SUFFIX ".dll"
        )
    endif()
else()
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
endif()

#=============================================================================
# Installation
#=============================================================================

if(WIN32)
    # Install to user IDA plugins directory on Windows
    install(TARGETS ${PROJECT_NAME}
            RUNTIME DESTINATION "$ENV{APPDATA}/Hex-Rays/IDA Pro/plugins"
            OPTIONAL
    )

    # Install to specific IDA installation directory (if it exists)
    set(IDA_SPECIFIC_DIR "C:/Program Files/IDA Pro 9.1/plugins")
    if(EXISTS "${IDA_SPECIFIC_DIR}")
        install(TARGETS ${PROJECT_NAME}
                RUNTIME DESTINATION "${IDA_SPECIFIC_DIR}"
        )
    endif()
else()
    # Install to user IDA plugins directory (~/.idapro/plugins)
    install(TARGETS ${PROJECT_NAME}
            LIBRARY DESTINATION "$ENV{HOME}/.idapro/plugins"
            OPTIONAL
    )

    # Install to specific IDA installation directory (if it exists)
    set(IDA_SPECIFIC_DIR "$ENV{HOME}/Downloads/Software/IDAPro/ida-pro-9.1/plugins")
    if(EXISTS "${IDA_SPECIFIC_DIR}")
        install(TARGETS ${PROJECT_NAME}
                LIBRARY DESTINATION "${IDA_SPECIFIC_DIR}"
        )
    endif()
endif()

# Install to custom IDA plugins directory (optional)
if(DEFINED IDA_INSTALL_DIR)
    if(WIN32)
        install(TARGETS ${PROJECT_NAME}
                RUNTIME DESTINATION "${IDA_INSTALL_DIR}/plugins"
        )
    else()
        install(TARGETS ${PROJECT_NAME}
                LIBRARY DESTINATION "${IDA_INSTALL_DIR}/plugins"
        )
    endif()
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
