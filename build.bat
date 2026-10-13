@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo Compilando AntigravityBridge do repositorio Git
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
echo [2/2] Gerando executavel standalone (Onefile com UAC Admin)...
python -m PyInstaller ^
    --uac-admin ^
    --noconsole ^
    --onefile ^
    --icon="icon.ico" ^
    --name="AntigravityBridge" ^
    --distpath="C:\Utilitario" ^
    --workpath="C:\Utilitario\build" ^
    --specpath="C:\Utilitario" ^
    --exclude-module=torch ^
    --exclude-module=torchvision ^
    --exclude-module=cv2 ^
    --exclude-module=scipy ^
    --exclude-module=pandas ^
    app.py

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================================
    echo Sucesso! Executavel atualizado em:
    echo C:\Utilitario\AntigravityBridge.exe
    echo ========================================================
) else (
    echo.
    echo [ERRO] Falha ao compilar com PyInstaller.
    exit /b 1
)
