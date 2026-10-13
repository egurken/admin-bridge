@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo Compilando AntigravityBridge no repositorio Git
echo Repositorio: %~dp0
echo ========================================================

cd /d "%~dp0"

echo [1/2] Executando testes de seguranca...
python test_security_rules.py
if %ERRORLEVEL% NEQ 0 (
    echo [ERRO] Os testes de seguranca falharam. Abortando compilacao.
    exit /b 1
)

echo.
echo [2/2] Gerando executavel standalone (Onefile)...
python -m PyInstaller ^
    --noconsole ^
    --onefile ^
    --icon="%~dp0icon.ico" ^
    --name="AntigravityBridge" ^
    --distpath="%~dp0dist" ^
    --workpath="%~dp0build" ^
    --specpath="%~dp0" ^
    --exclude-module=torch ^
    --exclude-module=torchvision ^
    --exclude-module=cv2 ^
    --exclude-module=scipy ^
    --exclude-module=pandas ^
    app.py

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================================
    echo Sucesso! Executavel gerado em:
    echo %~dp0dist\AntigravityBridge.exe
    echo ========================================================

    set "DESK_DIR="
    if exist "%USERPROFILE%\OneDrive\Desktop" (
        set "DESK_DIR=%USERPROFILE%\OneDrive\Desktop"
    ) else if exist "%USERPROFILE%\Desktop" (
        set "DESK_DIR=%USERPROFILE%\Desktop"
    )

    if defined DESK_DIR (
        echo Copiando para a Area de Trabalho: !DESK_DIR!\AntigravityBridge.exe
        copy /y "%~dp0dist\AntigravityBridge.exe" "!DESK_DIR!\AntigravityBridge.exe" >nul
        echo Executavel copiado para a Area de Trabalho com sucesso!
    )
) else (
    echo.
    echo [ERRO] Falha ao compilar com PyInstaller.
    exit /b 1
)
