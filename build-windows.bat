@echo off
REM Windows packaged-distribution build for lancer-nmap.
REM Output: dist\lancer-nmap-windows-x86_64\bin\*.exe

setlocal
echo === Building lancer-nmap (release, workspace) for Windows x86_64 ===
cargo build --release --workspace
if errorlevel 1 exit /b 1

echo === Packaging ===
set DIST=dist\lancer-nmap-windows-x86_64
if exist "%DIST%" rmdir /s /q "%DIST%"
mkdir "%DIST%"
mkdir "%DIST%\bin"

for %%B in (lancer-nmap.exe lancer-nmap-cli.exe lancer-ndiff.exe lancer-ncat.exe lancer-nping.exe) do (
    if exist "target\release\%%B" copy /Y "target\release\%%B" "%DIST%\bin\" >NUL
)
if exist LICENSE  copy /Y LICENSE  "%DIST%\" >NUL
if exist README.md copy /Y README.md "%DIST%\" >NUL

echo === Done. Binaries: ===
dir "%DIST%\bin"
exit /b 0
