@echo off
setlocal enabledelayedexpansion
title lancer-nmap Build

REM ============================================================
REM  build.bat -- Build the entire lancer-nmap workspace for Windows
REM  Output:
REM    build\lancer-nmap.exe       (GUI + CLI entrypoint)
REM    build\lancer-nmap-cli.exe   (pure CLI binary)
REM    build\lancer-ndiff.exe      (scan diff)
REM    build\lancer-ncat.exe       (netcat replacement)
REM    build\lancer-nping.exe      (packet crafter)
REM
REM  Requirements:
REM    - Rust toolchain   https://rustup.rs
REM    - Visual C++ Build Tools (2019 / 2022)
REM    - (optional) Npcap SDK    https://npcap.com   for raw send support
REM ============================================================

set "REPO=%~dp0"
set "REPO=%REPO:~0,-1%"
set "BUILD=%REPO%\build"

echo.
echo  ================================================
echo    lancer-nmap workspace build
echo  ================================================
echo.
echo  Repo   : %REPO%
echo  Output : %BUILD%
echo.

REM Locate cargo
where cargo >NUL 2>&1
if errorlevel 1 (
    set "CARGO=%USERPROFILE%\.cargo\bin\cargo.exe"
    if not exist "!CARGO!" (
        echo  ERROR: cargo not found.
        echo  Install Rust from https://rustup.rs then re-run.
        pause
        exit /b 1
    )
) else (
    set "CARGO=cargo"
)

echo  [1/2] Building release workspace...
"!CARGO!" build --release --workspace
if errorlevel 1 (
    echo  ERROR: cargo build failed
    pause
    exit /b 1
)

echo  [2/2] Collecting binaries...
if not exist "%BUILD%" mkdir "%BUILD%"
for %%B in (lancer-nmap.exe lancer-nmap-cli.exe lancer-ndiff.exe lancer-ncat.exe lancer-nping.exe) do (
    if exist "%REPO%\target\release\%%B" copy /Y "%REPO%\target\release\%%B" "%BUILD%\" >NUL
)

echo.
echo  ================================================
echo    Done!  Binaries copied to:
echo.
echo    %BUILD%\
echo  ================================================
echo.
pause
endlocal
