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
    --icon="icon.ico" ^
    --add-data="icon.ico;." ^
    --name="AntigravityBridge" ^
    --distpath="dist" ^
    --workpath="build" ^
    --specpath="." ^
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

    echo Copiando para C:\Utilitario\AntigravityBridge.exe...
    if exist "C:\Utilitario\AntigravityBridge.exe" (
        del /f /q "C:\Utilitario\AntigravityBridge.old.exe" 2>nul
        move /y "C:\Utilitario\AntigravityBridge.exe" "C:\Utilitario\AntigravityBridge.old.exe" >nul 2>nul
    )
    copy /y "%~dp0dist\AntigravityBridge.exe" "C:\Utilitario\AntigravityBridge.exe" >nul
    echo Executavel copiado para C:\Utilitario com sucesso!

    set "DESK_DIR="
    if exist "%USERPROFILE%\OneDrive\Desktop" (
        set "DESK_DIR=%USERPROFILE%\OneDrive\Desktop"
    ) else if exist "%USERPROFILE%\Desktop" (
        set "DESK_DIR=%USERPROFILE%\Desktop"
    )

    if defined DESK_DIR (
        echo Copiando para a Area de Trabalho: !DESK_DIR!\AntigravityBridge.exe
        if exist "!DESK_DIR!\AntigravityBridge.exe" (
            del /f /q "!DESK_DIR!\AntigravityBridge.old.exe" 2>nul
            move /y "!DESK_DIR!\AntigravityBridge.exe" "!DESK_DIR!\AntigravityBridge.old.exe" >nul 2>nul
        )
        copy /y "%~dp0dist\AntigravityBridge.exe" "!DESK_DIR!\AntigravityBridge.exe" >nul
        echo Executavel copiado para a Area de Trabalho com sucesso!
    )
) else (
    echo.
    echo [ERRO] Falha ao compilar com PyInstaller.
    exit /b 1
)
