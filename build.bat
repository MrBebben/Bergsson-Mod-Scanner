@echo off
rem Builds BergssonModScanner.exe (MSVC x64). Run from any prompt; finds Visual Studio if cl isn't on PATH.
setlocal
cd /d "%~dp0"

where cl >nul 2>nul
if errorlevel 1 (
  for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
  if not defined VSDIR ( echo Visual Studio C++ build tools not found. & exit /b 1 )
  call "%%VSDIR%%\VC\Auxiliary\Build\vcvars64.bat" >nul
)

set IMGUI=third_party\imgui
if not exist "%IMGUI%\imgui.cpp" ( echo Dear ImGui missing: git clone --depth 1 --branch v1.91.8 https://github.com/ocornut/imgui %IMGUI% & exit /b 1 )
if not exist build mkdir build

cl /nologo /std:c++17 /O2 /EHsc /utf-8 /DNDEBUG /W3 /MP /Fobuild\ /I%IMGUI% /I%IMGUI%\backends ^
   bergsson.cpp %IMGUI%\imgui.cpp %IMGUI%\imgui_draw.cpp %IMGUI%\imgui_tables.cpp %IMGUI%\imgui_widgets.cpp ^
   %IMGUI%\backends\imgui_impl_win32.cpp %IMGUI%\backends\imgui_impl_dx11.cpp ^
   /Fe:BergssonModScanner.exe /link /MANIFEST:EMBED
