# Building IDA Pro MCP Server

This document provides build instructions for all platforms.

## Quick Start

### Linux Users

```bash
# Build Linux version only
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j$(nproc)
cmake --install .
```

### Windows Users

See [BUILD_WINDOWS.md](BUILD_WINDOWS.md) for detailed Windows build instructions.

### Cross-Compiling from Linux to Windows

```bash
# Build both Linux and Windows versions
./build-all.sh

# Or build Windows only
./build-all.sh --windows-only
```

See [CROSS_COMPILE.md](CROSS_COMPILE.md) for detailed cross-compilation setup.

## Build System Overview

This project uses CMake and supports:
- **Native Linux builds** (GCC/Clang)
- **Native Windows builds** (Visual Studio, MinGW)
- **Cross-compilation** from Linux to Windows (MinGW-w64)

## Platform-Specific Guides

| Platform | Build From | Guide |
|----------|-----------|-------|
| Linux (.so) | Linux | [This document](#linux-build) |
| Windows (.dll) | Windows | [BUILD_WINDOWS.md](BUILD_WINDOWS.md) |
| Windows (.dll) | Linux | [CROSS_COMPILE.md](CROSS_COMPILE.md) |

## Linux Build

### Prerequisites

- CMake 3.27+
- GCC/Clang with C++20 support
- IDA Pro SDK 9.1
- OpenSSL development files

**Gentoo:**
```bash
emerge dev-util/cmake dev-libs/openssl
```

**Ubuntu/Debian:**
```bash
sudo apt install build-essential cmake libssl-dev
```

**Fedora:**
```bash
sudo dnf install cmake gcc-c++ openssl-devel
```

### Build Steps

1. **Set IDA SDK path** (if not in default location):
   ```bash
   export IDASDK=/path/to/idaprosdk91
   ```

2. **Configure and build**:
   ```bash
   mkdir build && cd build
   cmake .. -DCMAKE_BUILD_TYPE=Release
   cmake --build . -j$(nproc)
   ```

3. **Install**:
   ```bash
   cmake --install .
   ```

   Or manually:
   ```bash
   cp ida_mcp_plugin64.so ~/.idapro/plugins/
   ```

### Build Options

- **Debug build**:
  ```bash
  cmake .. -DCMAKE_BUILD_TYPE=Debug
  ```

- **Custom IDA SDK path**:
  ```bash
  cmake .. -DIDASDK=/path/to/sdk
  ```

- **Custom install location**:
  ```bash
  cmake .. -DIDA_INSTALL_DIR=/opt/ida-pro
  ```

## Windows Build

For building on Windows with Visual Studio, see [BUILD_WINDOWS.md](BUILD_WINDOWS.md).

## Cross-Compilation (Linux → Windows)

For cross-compiling Windows DLLs on Linux, see [CROSS_COMPILE.md](CROSS_COMPILE.md).

### Quick Cross-Compile

If you have MinGW-w64 and OpenSSL set up:

```bash
./build-all.sh
```

This builds both:
- `build-linux/ida_mcp_plugin64.so`
- `build-windows/ida_mcp_plugin64.dll`

## Build Artifacts

After building, you'll have:

### Linux
```
build/ida_mcp_plugin64.so
```

### Windows
```
build/ida_mcp_plugin64.dll
```

## Installation Locations

### Linux
- User: `~/.idapro/plugins/`
- System: `$IDADIR/plugins/`

### Windows
- User: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
- System: `C:\Program Files\IDA Pro 9.1\plugins\`

## Verifying Installation

1. Start IDA Pro
2. Load any binary
3. Go to **Edit > Plugins** (or press `Ctrl+3`)
4. Look for "IDA Pro MCP Server"

If you don't see it, check the IDA Pro output window for error messages.

## Troubleshooting

### CMake Can't Find IDA SDK

```bash
cmake .. -DIDASDK=/path/to/idaprosdk91
```

Or set environment variable:
```bash
export IDASDK=/path/to/idaprosdk91
```

### OpenSSL Not Found

**Linux:**
```bash
# Ubuntu/Debian
sudo apt install libssl-dev

# Fedora
sudo dnf install openssl-devel

# Gentoo
emerge dev-libs/openssl
```

**Windows cross-compile:**
See [CROSS_COMPILE.md](CROSS_COMPILE.md) for MinGW OpenSSL setup.

### Plugin Fails to Load

1. Check IDA Pro output window for errors
2. Verify IDA SDK version matches your IDA Pro version
3. Ensure all dependencies are available:
   ```bash
   # Linux
   ldd ida_mcp_plugin64.so

   # Windows (cross-compile check)
   x86_64-w64-mingw32-objdump -p ida_mcp_plugin64.dll | grep "DLL Name"
   ```

### Build Fails with C++ Standard Errors

Ensure you have a compiler with C++20 support:
- GCC 10+
- Clang 10+
- Visual Studio 2019+
- MinGW-w64 with GCC 10+

## Advanced Build Options

### Using Ninja (Faster Builds)

```bash
cmake .. -G Ninja
ninja
```

### Static Linking

For Windows cross-compile with minimal dependencies:
```bash
cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw64.cmake \
    -DBUILD_SHARED_LIBS=OFF \
    -DOPENSSL_USE_STATIC_LIBS=ON
```

### Custom Compiler

```bash
cmake .. \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++
```

### Verbose Build

```bash
cmake --build . --verbose
```

## Build Scripts

- `build-all.sh` - Build both Linux and Windows versions
- `install.sh` - Install Linux plugin
- `install.bat` - Install Windows plugin (run on Windows)

## Clean Build

```bash
# Remove build directories
rm -rf build build-linux build-windows

# Or use the build script
./build-all.sh --clean
```

## CI/CD

Example GitHub Actions workflow:

```yaml
name: Build

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: |
          sudo apt update
          sudo apt install -y cmake mingw-w64 libssl-dev
      - name: Build all platforms
        run: |
          ./build-all.sh
      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: plugins
          path: |
            build-linux/ida_mcp_plugin64.so
            build-windows/ida_mcp_plugin64.dll
```

## Development

### Building with Debug Symbols

```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug
```

### Building with Sanitizers (Linux only)

```bash
cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_FLAGS="-fsanitize=address -fsanitize=undefined"
```

### Rebuilding Only Changed Files

```bash
cmake --build . -j$(nproc)
```

CMake automatically detects changed files.

## Getting Help

- Build issues: Check the troubleshooting section above
- Platform-specific issues: See platform-specific guides
- IDA SDK issues: Consult IDA Pro SDK documentation
- Other issues: Open an issue on the project repository
