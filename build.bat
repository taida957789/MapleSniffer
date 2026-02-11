@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
cd /d C:\Users\tasi\source\repos\MapleSniffer

echo === CMake Configure ===
cmake --preset x64-debug
if errorlevel 1 (
    echo CMake configure FAILED
    exit /b 1
)

echo === CMake Build ===
cmake --build out/build/x64-debug
if errorlevel 1 (
    echo CMake build FAILED
    exit /b 1
)

echo === Build SUCCESS ===
