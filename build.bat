@echo off
where cl >nul 2>nul
if %errorlevel% == 0 (
    cl /nologo /std:c++20 /EHsc /O2 /GS /guard:cf /Feauth_client.exe client\main.cpp /link /guard:cf
    goto :done
)
where g++ >nul 2>nul
if %errorlevel% == 0 (
    g++ -std=c++20 -O2 -o auth_client.exe client\main.cpp -lws2_32 -lncrypt -lbcrypt -ladvapi32
    goto :done
)
echo [BUILD] No compiler found. Install MSVC or MinGW.
exit /b 1
:done
echo [BUILD] auth_client.exe ready.
