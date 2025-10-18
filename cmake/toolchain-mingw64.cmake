# Toolchain file for cross-compiling to Windows from Linux using MinGW-w64
# Usage: cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw64.cmake ..

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Specify the cross compiler
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)

# Get the MinGW sysroot
execute_process(
    COMMAND ${CMAKE_C_COMPILER} -print-sysroot
    OUTPUT_VARIABLE MINGW_SYSROOT
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Where to look for the target environment
set(MINGW_USR_ROOT "/usr/x86_64-w64-mingw32/usr")
set(CMAKE_FIND_ROOT_PATH ${MINGW_SYSROOT} ${MINGW_USR_ROOT})
set(CMAKE_PREFIX_PATH ${MINGW_SYSROOT} ${MINGW_USR_ROOT})

# Search for programs in the build host directories
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# Search for libraries and headers in the target directories
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Set Windows-specific flags
set(CMAKE_CXX_FLAGS_INIT "-static-libgcc -static-libstdc++")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-static-libgcc -static-libstdc++")

# OpenSSL configuration for MinGW
# Point CMake to the MinGW OpenSSL installation
set(OPENSSL_ROOT_DIR "${MINGW_USR_ROOT}" CACHE PATH "OpenSSL root directory")
set(OPENSSL_INCLUDE_DIR "${MINGW_USR_ROOT}/include" CACHE PATH "OpenSSL include directory")
set(OPENSSL_CRYPTO_LIBRARY "${MINGW_USR_ROOT}/lib/libcrypto.dll.a" CACHE FILEPATH "OpenSSL crypto library")
set(OPENSSL_SSL_LIBRARY "${MINGW_USR_ROOT}/lib/libssl.dll.a" CACHE FILEPATH "OpenSSL SSL library")
set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} CACHE STRING "OpenSSL libraries")

# Tell CMake this is cross-compiling
set(CMAKE_CROSSCOMPILING TRUE)
