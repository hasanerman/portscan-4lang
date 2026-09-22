@echo off
setlocal enabledelayedexpansion

rem kullanim: buildeverything.bat [test]
rem proje klasorunde calistirilirsa o projenin dort dilini derler,
rem ust klasorde calistirilirsa altindaki tum projeleri gezer.
rem "test" verilirse testler de calisir.

set "ROOT=%~dp0"
set "MODE=%~1"
set /a OK_COUNT=0
set /a FAIL_COUNT=0
set /a SKIP_COUNT=0
set "FAILED_LIST="

call :ensure_msvc
if errorlevel 1 exit /b 1

call :find_cmake
call :find_dotnet

set "SINGLE=0"
if exist "%ROOT%c\build.bat"        set "SINGLE=1"
if exist "%ROOT%cpp\CMakeLists.txt" set "SINGLE=1"
if exist "%ROOT%rust\Cargo.toml"    set "SINGLE=1"
if exist "%ROOT%csharp"             set "SINGLE=1"

echo.
echo ===============================================
if "!SINGLE!"=="1" (echo  toplu derleme - tek proje) else (echo  toplu derleme - tum projeler)
if /i "%MODE%"=="test" (echo  mod: derle ve test et) else (echo  mod: yalnizca derle)
echo ===============================================

if "!SINGLE!"=="1" (
    for %%i in ("%ROOT%.") do set "ROOT_NAME=%%~nxi"
    call :build_project "%ROOT%." "!ROOT_NAME!"
) else (
    for /d %%P in ("%ROOT%*-*") do call :build_project "%%~fP" "%%~nxP"
)

echo.
echo ===============================================
echo  basarili: !OK_COUNT!   basarisiz: !FAIL_COUNT!   atlanan: !SKIP_COUNT!
if !FAIL_COUNT! GTR 0 (
    echo  basarisiz olanlar:!FAILED_LIST!
    echo ===============================================
    exit /b 1
)
echo ===============================================
exit /b 0

:build_project
echo.
echo --- %~2 ---
if exist "%~1\c\build.bat"        call :build_c      "%~1" "%~2"
if exist "%~1\cpp\CMakeLists.txt" call :build_cpp    "%~1" "%~2"
if exist "%~1\rust\Cargo.toml"    call :build_rust   "%~1" "%~2"
if exist "%~1\csharp"             call :build_csharp "%~1" "%~2"
exit /b 0

:ensure_msvc
cl /? >nul 2>nul
if not errorlevel 1 exit /b 0

set "VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "!VSWHERE!" (
    echo MSVC bulunamadi. Visual Studio C++ araclarini kur veya Developer Command Prompt kullan.
    exit /b 1
)
for /f "usebackq tokens=*" %%i in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH (
    echo MSVC araclari kurulu degil.
    exit /b 1
)
call "!VSPATH!\VC\Auxiliary\Build\vcvars64.bat" >nul
exit /b 0

:find_cmake
set "CMAKE_EXE="
where cmake >nul 2>nul
if not errorlevel 1 (
    set "CMAKE_EXE=cmake"
    exit /b 0
)
if defined VSPATH (
    if exist "!VSPATH!\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" (
        set "CMAKE_EXE=!VSPATH!\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    )
)
exit /b 0

:find_dotnet
set "HAS_DOTNET=0"
where dotnet >nul 2>nul
if not errorlevel 1 set "HAS_DOTNET=1"
exit /b 0

:build_c
pushd "%~1\c"
echo [C]    derleniyor
if /i "%MODE%"=="test" (
    call "%~1\c\build.bat" test
) else (
    call "%~1\c\build.bat"
)
if errorlevel 1 (
    call :mark_fail "%~2 / c"
) else (
    call :mark_ok
)
popd
exit /b 0

:build_cpp
if not defined CMAKE_EXE (
    echo [C++]  atlandi: cmake bulunamadi
    call :mark_skip
    exit /b 0
)
pushd "%~1\cpp"
echo [C++]  derleniyor
"!CMAKE_EXE!" -S . -B build -A x64 >nul
if errorlevel 1 (
    call :mark_fail "%~2 / cpp (configure)"
    popd
    exit /b 0
)
"!CMAKE_EXE!" --build build --config Release
if errorlevel 1 (
    call :mark_fail "%~2 / cpp (build)"
    popd
    exit /b 0
)
if /i "%MODE%"=="test" (
    ctest --test-dir build -C Release --output-on-failure
    if errorlevel 1 (
        call :mark_fail "%~2 / cpp (test)"
        popd
        exit /b 0
    )
)
call :mark_ok
popd
exit /b 0

:build_rust
where cargo >nul 2>nul
if errorlevel 1 (
    echo [Rust] atlandi: cargo bulunamadi
    call :mark_skip
    exit /b 0
)
pushd "%~1\rust"
echo [Rust] derleniyor
cargo build --release
if errorlevel 1 (
    call :mark_fail "%~2 / rust"
    popd
    exit /b 0
)
if /i "%MODE%"=="test" (
    cargo test
    if errorlevel 1 (
        call :mark_fail "%~2 / rust (test)"
        popd
        exit /b 0
    )
)
call :mark_ok
popd
exit /b 0

:build_csharp
if "!HAS_DOTNET!"=="0" (
    echo [C#]   atlandi: dotnet bulunamadi
    call :mark_skip
    exit /b 0
)
pushd "%~1\csharp"
echo [C#]   derleniyor
rem vcvars Platform=x64 birakir, msbuild bunu cozum yapilandirmasi sanip patlar
set "Platform="
dotnet build -c Release --nologo
if errorlevel 1 (
    call :mark_fail "%~2 / csharp"
    popd
    exit /b 0
)
if /i "%MODE%"=="test" (
    dotnet test -c Release --nologo
    if errorlevel 1 (
        call :mark_fail "%~2 / csharp (test)"
        popd
        exit /b 0
    )
)
call :mark_ok
popd
exit /b 0

:mark_ok
set /a OK_COUNT+=1
exit /b 0

:mark_skip
set /a SKIP_COUNT+=1
exit /b 0

:mark_fail
set /a FAIL_COUNT+=1
set "FAILED_LIST=!FAILED_LIST! [%~1]"
echo        BASARISIZ: %~1
exit /b 0
