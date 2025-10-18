#!/bin/bash
# Build script for IDA Pro MCP Server
# Builds both Linux and Windows (cross-compiled) versions

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}============================================${NC}"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

# Parse command line arguments
BUILD_LINUX=1
BUILD_WINDOWS=1
INSTALL=0
CLEAN=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --linux-only)
            BUILD_WINDOWS=0
            shift
            ;;
        --windows-only)
            BUILD_LINUX=0
            shift
            ;;
        --install)
            INSTALL=1
            shift
            ;;
        --clean)
            CLEAN=1
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --linux-only      Build only Linux version"
            echo "  --windows-only    Build only Windows version (cross-compiled)"
            echo "  --install         Install plugins after building"
            echo "  --clean           Clean build directories before building"
            echo "  --help            Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Clean if requested
if [ $CLEAN -eq 1 ]; then
    print_header "Cleaning Build Directories"
    rm -rf build-linux build-windows
    print_success "Build directories cleaned"
    echo ""
fi

# Build Linux version
if [ $BUILD_LINUX -eq 1 ]; then
    print_header "Building Linux Version"

    mkdir -p build-linux
    cd build-linux

    print_info "Configuring CMake for Linux..."
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DIDASDK="$HOME/CLionProjects/idaprosdk91"

    print_info "Building Linux plugin..."
    cmake --build . -j$(nproc)

    if [ -f "ida_mcp_plugin64.so" ]; then
        print_success "Linux build completed: $(pwd)/ida_mcp_plugin64.so"

        if [ $INSTALL -eq 1 ]; then
            print_info "Installing Linux plugin..."
            cmake --install .
            print_success "Linux plugin installed"
        fi
    else
        print_error "Linux build failed!"
        exit 1
    fi

    cd ..
    echo ""
fi

# Build Windows version (cross-compiled)
if [ $BUILD_WINDOWS -eq 1 ]; then
    print_header "Building Windows Version (Cross-Compiled)"

    # Check if MinGW is installed
    if ! command -v x86_64-w64-mingw32-g++ &> /dev/null; then
        print_error "MinGW-w64 not found!"
        echo "Please install it first:"
        echo "  Gentoo: emerge crossdev && crossdev x86_64-w64-mingw32"
        echo "  Ubuntu/Debian: apt install mingw-w64"
        echo "  Fedora: dnf install mingw64-gcc mingw64-gcc-c++"
        exit 1
    fi

    # Check for Windows IDA SDK
    if [ ! -d "$HOME/CLionProjects/idaprosdk91" ]; then
        print_error "IDA SDK not found at: $HOME/CLionProjects/idaprosdk91"
        echo "Please set the correct path in this script or CMakeLists.txt"
        exit 1
    fi

    mkdir -p build-windows
    cd build-windows

    print_info "Configuring CMake for Windows (MinGW cross-compile)..."

    # Note: You may need to adjust the IDA SDK path for Windows libraries
    cmake .. \
        -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-mingw64.cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DIDASDK="$HOME/CLionProjects/idaprosdk91"

    print_info "Building Windows plugin..."
    cmake --build . -j$(nproc)

    if [ -f "ida_mcp_plugin64.dll" ]; then
        print_success "Windows build completed: $(pwd)/ida_mcp_plugin64.dll"

        # Show DLL dependencies
        if command -v x86_64-w64-mingw32-objdump &> /dev/null; then
            print_info "DLL dependencies:"
            x86_64-w64-mingw32-objdump -p ida_mcp_plugin64.dll | grep "DLL Name:" | sed 's/^/  /'
        fi

        if [ $INSTALL -eq 1 ]; then
            print_info "Note: Automatic Windows installation from Linux is not supported"
            print_info "Copy ida_mcp_plugin64.dll manually to your Windows IDA Pro plugins directory"
        fi
    else
        print_error "Windows build failed!"
        exit 1
    fi

    cd ..
    echo ""
fi

# Summary
print_header "Build Summary"

if [ $BUILD_LINUX -eq 1 ] && [ -f "build-linux/ida_mcp_plugin64.so" ]; then
    echo -e "${GREEN}✓${NC} Linux:   build-linux/ida_mcp_plugin64.so"
fi

if [ $BUILD_WINDOWS -eq 1 ] && [ -f "build-windows/ida_mcp_plugin64.dll" ]; then
    echo -e "${GREEN}✓${NC} Windows: build-windows/ida_mcp_plugin64.dll"
fi

echo ""
print_success "All builds completed successfully!"

if [ $INSTALL -eq 0 ]; then
    echo ""
    print_info "To install, run: $0 --install"
fi
