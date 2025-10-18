@echo off
REM IDA Pro MCP Server Plugin - Windows Installation Script

echo ============================================
echo IDA Pro MCP Server Plugin Installer
echo ============================================
echo.

REM Check if build directory exists
if not exist "build" (
    echo ERROR: build directory not found!
    echo Please build the project first using CMake.
    echo.
    echo Run: mkdir build ^&^& cd build ^&^& cmake .. ^&^& cmake --build . --config Release
    exit /b 1
)

REM Find the built DLL
set DLL_NAME=ida_mcp_plugin64.dll
set DLL_PATH=

REM Check common build output locations
if exist "build\Release\%DLL_NAME%" (
    set DLL_PATH=build\Release\%DLL_NAME%
) else if exist "build\%DLL_NAME%" (
    set DLL_PATH=build\%DLL_NAME%
) else (
    echo ERROR: Could not find %DLL_NAME%
    echo Checked locations:
    echo   - build\Release\%DLL_NAME%
    echo   - build\%DLL_NAME%
    echo.
    echo Please ensure the plugin was built successfully.
    exit /b 1
)

echo Found plugin: %DLL_PATH%
echo.

REM Install to user plugins directory
set USER_PLUGINS=%APPDATA%\Hex-Rays\IDA Pro\plugins

echo Installing to user plugins directory...
if not exist "%USER_PLUGINS%" (
    echo Creating directory: %USER_PLUGINS%
    mkdir "%USER_PLUGINS%"
)

echo Copying %DLL_PATH% to %USER_PLUGINS%
copy /Y "%DLL_PATH%" "%USER_PLUGINS%\" >nul
if %ERRORLEVEL% EQU 0 (
    echo [OK] Installed to: %USER_PLUGINS%\%DLL_NAME%
) else (
    echo [FAILED] Could not copy to user plugins directory
)
echo.

REM Try to install to program files (requires admin)
set PROGRAM_PLUGINS=C:\Program Files\IDA Pro 9.1\plugins

if exist "%PROGRAM_PLUGINS%" (
    echo Installing to IDA Pro installation directory...
    echo This may require administrator privileges.

    copy /Y "%DLL_PATH%" "%PROGRAM_PLUGINS%\" >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo [OK] Installed to: %PROGRAM_PLUGINS%\%DLL_NAME%
    ) else (
        echo [SKIPPED] No write permission to %PROGRAM_PLUGINS%
        echo         (This is normal if not running as administrator)
    )
) else (
    echo [INFO] IDA Pro installation not found at: %PROGRAM_PLUGINS%
)
echo.

REM Check for other common IDA Pro installation paths
for %%D in (
    "C:\Program Files\IDA Professional 9.1\plugins"
    "C:\Program Files\IDA Freeware 9.1\plugins"
    "C:\IDA Pro 9.1\plugins"
) do (
    if exist %%D (
        echo Found additional IDA installation: %%~D
        copy /Y "%DLL_PATH%" %%D >nul 2>&1
        if %ERRORLEVEL% EQU 0 (
            echo [OK] Installed to: %%~D\%DLL_NAME%
        )
    )
)

echo.
echo ============================================
echo Installation Complete
echo ============================================
echo.
echo The plugin has been installed to your IDA Pro plugins directory.
echo.
echo To verify installation:
echo   1. Start IDA Pro
echo   2. Open any binary file
echo   3. Go to Edit ^> Plugins
echo   4. Look for "IDA Pro MCP Server"
echo.
echo If you don't see the plugin, check:
echo   - IDA Pro output window for error messages
echo   - Plugin is in: %USER_PLUGINS%
echo   - All required DLL dependencies are available (OpenSSL)
echo.
pause
