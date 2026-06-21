@echo off
setlocal

set EDK2=C:\edk2
set BUILD_TARGET=RELEASE
set TOOLCHAIN=VS2026
set ARCH=X64
set DSC=%EDK2%\SingularityPkg\SingularityPkg.dsc

echo === Step 1: Setup EDK2 environment ===
cd /d "%EDK2%"
call edksetup.bat

echo.
echo === Step 2: Build Singularity DXE ===
call build ^
  -p "%DSC%" ^
  -a %ARCH% ^
  -b %BUILD_TARGET% ^
  -t %TOOLCHAIN%

echo.
echo === Step 3: Check output ===

set OUT=%EDK2%\Build\SingularityPkg\%BUILD_TARGET%_%TOOLCHAIN%\%ARCH%\SingularityDxe.efi

if exist "%OUT%" (
    echo Success! Output: %OUT%
) else (
    echo FAILED: EFI not found
    echo Check Build\SingularityPkg\
)

pause