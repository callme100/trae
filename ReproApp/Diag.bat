@echo off
echo === Test 1: Default (PGO on, ReadyToRun on) ===
c:\trae\ReproApp\bin\Release\net8.0\ReproApp.exe prewarm
echo.
echo === Test 2: PGO OFF ===
set DOTNET_TieredPGO=0
c:\trae\ReproApp\bin\Release\net8.0\ReproApp.exe prewarm
set DOTNET_TieredPGO=
echo.
echo === Test 3: ReadyToRun OFF ===
set DOTNET_ReadyToRun=0
c:\trae\ReproApp\bin\Release\net8.0\ReproApp.exe prewarm
set DOTNET_ReadyToRun=
echo.
echo === Test 4: Tiered OFF ===
set DOTNET_TieredCompilation=0
c:\trae\ReproApp\bin\Release\net8.0\ReproApp.exe prewarm
set DOTNET_TieredCompilation=
echo.
echo === Test 5: All optimization OFF ===
set DOTNET_TieredCompilation=0
set DOTNET_TieredPGO=0
set DOTNET_ReadyToRun=0
c:\trae\ReproApp\bin\Release\net8.0\ReproApp.exe prewarm
set DOTNET_TieredCompilation=
set DOTNET_TieredPGO=
set DOTNET_ReadyToRun=
