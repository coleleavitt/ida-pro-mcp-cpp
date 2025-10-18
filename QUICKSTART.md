# Quick Start - Building IDA Pro MCP Server

## TL;DR

### Linux Users

```bash
# Build and install Linux plugin
./build-all.sh --linux-only --install
```

### Build Both Linux and Windows (Cross-Compile)

```bash
# Prerequisites (Gentoo)
sudo x86_64-w64-mingw32-emerge -av dev-libs/openssl

# Build both platforms
./build-all.sh

# Outputs:
# - build-linux/ida_mcp_plugin64.so
# - build-windows/ida_mcp_plugin64.dll
```

### Windows Users (Building on Windows)

See [BUILD_WINDOWS.md](BUILD_WINDOWS.md)

## What You Get

After building, you'll have:

- **Linux**: `build-linux/ida_mcp_plugin64.so` (2.6 MB)
- **Windows**: `build-windows/ida_mcp_plugin64.dll` (4.2 MB)

## Installation

### Linux
```bash
cp build-linux/ida_mcp_plugin64.so ~/.idapro/plugins/
```

### Windows
```cmd
copy build-windows\ida_mcp_plugin64.dll "%APPDATA%\Hex-Rays\IDA Pro\plugins\"
```

Or use the install scripts:
- Linux: `./install.sh`
- Windows: `install.bat`

## Dependencies

The Windows DLL requires these runtime DLLs (place in IDA Pro directory):
- `libcrypto-3-x64.dll`
- `libssl-3-x64.dll`

Get them from your MinGW OpenSSL installation or download from:
- https://slproweb.com/products/Win32OpenSSL.html

## Verification

1. Start IDA Pro
2. Load any binary
3. Press `Ctrl+3` or go to **Edit > Plugins**
4. Look for "IDA Pro MCP Server"

## Detailed Guides

- [BUILD.md](BUILD.md) - General build instructions
- [BUILD_WINDOWS.md](BUILD_WINDOWS.md) - Building on Windows with Visual Studio
- [CROSS_COMPILE.md](CROSS_COMPILE.md) - Cross-compiling Windows DLLs from Linux

## Troubleshooting

### "OpenSSL not found" on Linux cross-compile

```bash
# Gentoo
sudo x86_64-w64-mingw32-emerge -av dev-libs/openssl

# Ubuntu/Debian
sudo apt install mingw-w64 mingw-w64-tools

# Then use vcpkg (see CROSS_COMPILE.md)
./setup-mingw-deps.sh
./build-windows-vcpkg.sh
```

### "Plugin failed to load" in IDA Pro

Check the IDA Pro output window for errors. Common issues:
- Missing OpenSSL DLLs (Windows)
- Wrong IDA SDK version
- Architecture mismatch (32-bit vs 64-bit)

## Build Options

```bash
# Build only Linux
./build-all.sh --linux-only

# Build only Windows (cross-compile)
./build-all.sh --windows-only

# Build both platforms
./build-all.sh

# Clean and rebuild
./build-all.sh --clean

# Build and install
./build-all.sh --install
```

## Next Steps

After installing the plugin, configure it for use with Claude Desktop. See the main README for configuration instructions.
