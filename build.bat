@echo off
setlocal
echo [*] Building IronVeil (x64 Release)...

if not exist build mkdir build
cd build

cmake -A x64 ..
if %ERRORLEVEL% NEQ 0 (
    echo [-] CMake configuration failed.
    pause
    exit /b %ERRORLEVEL%
)

cmake --build . --config Release
if %ERRORLEVEL% NEQ 0 (
    echo [-] Build failed.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo [+] Build successful! Binaries located in bin/Release/
pause
