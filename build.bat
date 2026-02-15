@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
cd /d C:\Users\tasi\source\repos\MapleSniffer

set PATH=C:\Users\tasi\AppData\Roaming\nvm\v22.22.0;%PATH%

echo === Frontend Build ===
pushd frontend
call npm run build
if errorlevel 1 (
    echo Frontend build FAILED
    exit /b 1
)
popd

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
