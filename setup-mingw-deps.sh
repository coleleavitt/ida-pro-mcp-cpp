#!/bin/bash
# Setup script for MinGW cross-compilation dependencies
# Installs OpenSSL for Windows cross-compilation using vcpkg

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VCPKG_DIR="${VCPKG_DIR:-$HOME/vcpkg}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

# Check if MinGW is installed
if ! command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    print_error "MinGW-w64 is not installed!"
    echo ""
    echo "Install it with:"
    echo "  Gentoo:        emerge crossdev && crossdev x86_64-w64-mingw32"
    echo "  Ubuntu/Debian: sudo apt install mingw-w64"
    echo "  Fedora:        sudo dnf install mingw64-gcc mingw64-gcc-c++"
    echo "  Arch:          sudo pacman -S mingw-w64-gcc"
    exit 1
fi

print_success "MinGW-w64 found: $(x86_64-w64-mingw32-g++ --version | head -1)"
echo ""

# Check if vcpkg is already installed
if [ -d "$VCPKG_DIR" ]; then
    print_info "vcpkg found at: $VCPKG_DIR"
else
    print_header "Installing vcpkg"

    print_info "Cloning vcpkg to $VCPKG_DIR..."
    git clone https://github.com/Microsoft/vcpkg.git "$VCPKG_DIR"

    print_info "Bootstrapping vcpkg..."
    "$VCPKG_DIR/bootstrap-vcpkg.sh"

    print_success "vcpkg installed successfully"
    echo ""
fi

# Install OpenSSL for MinGW
print_header "Installing OpenSSL for MinGW"

print_info "Installing openssl:x64-mingw-static..."
"$VCPKG_DIR/vcpkg" install openssl:x64-mingw-static

if [ $? -eq 0 ]; then
    print_success "OpenSSL installed for MinGW"
else
    print_error "Failed to install OpenSSL"
    exit 1
fi

echo ""

# Create a helper script for building
VCPKG_CMAKE_TOOLCHAIN="$VCPKG_DIR/scripts/buildsystems/vcpkg.cmake"
MINGW_TOOLCHAIN="$SCRIPT_DIR/cmake/toolchain-mingw64.cmake"

cat > "$SCRIPT_DIR/build-windows-vcpkg.sh" << 'EOF'
#!/bin/bash
# Build Windows version using vcpkg dependencies

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VCPKG_DIR="${VCPKG_DIR:-$HOME/vcpkg}"

if [ ! -d "$VCPKG_DIR" ]; then
    echo "ERROR: vcpkg not found at $VCPKG_DIR"
    echo "Run ./setup-mingw-deps.sh first"
    exit 1
fi

mkdir -p build-windows
cd build-windows

cmake .. \
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_DIR/scripts/buildsystems/vcpkg.cmake" \
    -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE="$SCRIPT_DIR/cmake/toolchain-mingw64.cmake" \
    -DVCPKG_TARGET_TRIPLET=x64-mingw-static \
    -DCMAKE_BUILD_TYPE=Release \
    -DIDASDK="${IDASDK:-$HOME/CLionProjects/idaprosdk91}"

cmake --build . -j$(nproc)

if [ -f "ida_mcp_plugin64.dll" ]; then
    echo ""
    echo "Build successful: $(pwd)/ida_mcp_plugin64.dll"

    # Show dependencies
    if command -v x86_64-w64-mingw32-objdump &> /dev/null; then
        echo ""
        echo "DLL Dependencies:"
        x86_64-w64-mingw32-objdump -p ida_mcp_plugin64.dll | grep "DLL Name:" | sed 's/^/  /'
    fi
else
    echo "Build failed!"
    exit 1
fi
EOF

chmod +x "$SCRIPT_DIR/build-windows-vcpkg.sh"

print_success "Created build-windows-vcpkg.sh"
echo ""

# Summary
print_header "Setup Complete"

echo "Dependencies installed:"
echo "  ✓ vcpkg: $VCPKG_DIR"
echo "  ✓ OpenSSL for MinGW: $VCPKG_DIR/installed/x64-mingw-static"
echo ""
echo "You can now build the Windows version using:"
echo ""
echo "  Method 1 (Recommended - uses vcpkg):"
echo "    ./build-windows-vcpkg.sh"
echo ""
echo "  Method 2 (build-all.sh with vcpkg):"
echo "    export VCPKG_DIR=$VCPKG_DIR"
echo "    ./build-all.sh --windows-only"
echo ""
echo "  Method 3 (Manual with vcpkg):"
echo "    mkdir build-windows && cd build-windows"
echo "    cmake .. \\"
echo "      -DCMAKE_TOOLCHAIN_FILE=$VCPKG_CMAKE_TOOLCHAIN \\"
echo "      -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE=$MINGW_TOOLCHAIN \\"
echo "      -DVCPKG_TARGET_TRIPLET=x64-mingw-static"
echo "    cmake --build ."
echo ""

print_info "If you want to use the integrated build script, update build-all.sh"
print_info "to use vcpkg by adding the CMAKE_TOOLCHAIN_FILE arguments shown above."
