@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo Compilando Admin Bridge Versao DEBUG no repositorio Git
echo Repositorio: %~dp0
echo ========================================================

cd /d "%~dp0"

echo.
echo Gerando executavel standalone DEBUG [Com janela de console]...
python -m PyInstaller ^
    --console ^
    --onefile ^
    --icon="icon.ico" ^
    --add-data="icon.ico;." ^
    --name="AdminBridge_Debug" ^
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
    echo Sucesso! Executavel Debug gerado em:
    echo %~dp0dist\AdminBridge_Debug.exe
    echo ========================================================

    set "DESK_DIR="
    if exist "%USERPROFILE%\OneDrive\Desktop" (
        set "DESK_DIR=%USERPROFILE%\OneDrive\Desktop"
    ) else if exist "%USERPROFILE%\Desktop" (
        set "DESK_DIR=%USERPROFILE%\Desktop"
    )

    if defined DESK_DIR (
        echo Copiando versao DEBUG para a Area de Trabalho: !DESK_DIR!
        copy /y "%~dp0dist\AdminBridge_Debug.exe" "!DESK_DIR!\AdminBridge_Debug.exe" >nul
        echo Executavel AdminBridge_Debug.exe copiado com sucesso para a Area de Trabalho!
    )
) else (
    echo.
    echo [ERRO] Falha ao compilar versao debug com PyInstaller.
    exit /b 1
)
