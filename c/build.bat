@echo off
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
set "OUT=%ROOT%build"
set "CFLAGS=/nologo /W4 /WX /O2 /MT /D_CRT_SECURE_NO_WARNINGS"
set "LIBS=ws2_32.lib"

set "VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"

cl /? >nul 2>nul
if errorlevel 1 (
  if not exist "!VSWHERE!" (
    echo MSVC not found. Run this from a Developer Command Prompt instead.
    exit /b 1
  )
  for /f "usebackq tokens=*" %%i in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
  if not defined VSPATH (
    echo MSVC build tools are not installed.
    exit /b 1
  )
  call "!VSPATH!\VC\Auxiliary\Build\vcvars64.bat" >nul
)

if not exist "%OUT%" mkdir "%OUT%"

set CORE="%ROOT%src\ports.c" "%ROOT%src\args.c" "%ROOT%src\net_addr.c" "%ROOT%src\net_sock.c" "%ROOT%src\scan.c" "%ROOT%src\pool.c" "%ROOT%src\report.c"

cl %CFLAGS% /Fe:"%OUT%\portscan.exe" /Fo:"%OUT%\\" "%ROOT%src\main.c" %CORE% %LIBS%
if errorlevel 1 exit /b 1

cl %CFLAGS% /Fe:"%OUT%\test_ports.exe" /Fo:"%OUT%\\" "%ROOT%tests\test_ports.c" %CORE% %LIBS%
if errorlevel 1 exit /b 1

cl %CFLAGS% /Fe:"%OUT%\test_scan.exe" /Fo:"%OUT%\\" "%ROOT%tests\test_scan.c" %CORE% %LIBS%
if errorlevel 1 exit /b 1

cl %CFLAGS% /Fe:"%OUT%\test_report.exe" /Fo:"%OUT%\\" "%ROOT%tests\test_report.c" %CORE% %LIBS%
if errorlevel 1 exit /b 1

if /i "%~1"=="test" (
  "%OUT%\test_ports.exe" || exit /b 1
  "%OUT%\test_scan.exe" || exit /b 1
  "%OUT%\test_report.exe" || exit /b 1
)

echo build complete: %OUT%
