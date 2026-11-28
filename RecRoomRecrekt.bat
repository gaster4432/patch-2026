@echo off
rem Launcher for the Recrekt flow.
rem
rem Launches Rec Room in screen (desktop) mode straight through the game's own import
rem binding: Referee.dll is Recrekt, which attaches every DLL in
rem preserve\modules\ on its own shortly after GameAssembly.dll appears.
rem No injector window, no remote threads.
rem
rem Requires:
rem   - Steam running (the client will not boot without it),
rem   - Install-Recrekt.bat already run in this folder.
setlocal
cd /d "%~dp0"

if not exist "preserve\Referee.dll" (
    echo [!] preserve\Referee.dll not found. Run Install-Recrekt.bat first.
    pause
    exit /b 1
)
if not exist "RecRoom.exe" (
    echo [!] RecRoom.exe not found next to this script.
    pause
    exit /b 1
)

echo Launching Rec Room (screen) via Recrekt...
start "" "RecRoom.exe" +forcemode:screen
