@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo Compilando Admin Bridge no repositorio Git
echo Repositorio: %~dp0
echo ========================================================

cd /d "%~dp0"

echo.
echo [1/2] Executando testes automatizados de seguranca...
python test_security_rules.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERRO CRITICO] Falha nos testes de seguranca! Compilacao abortada.
    pause
    exit /b 1
)

echo.
echo [2/2] Gerando executavel standalone (Onefile)...
python -m PyInstaller ^
    --noconsole ^
    --onefile ^
    --icon="icon.ico" ^
    --add-data="icon.ico;." ^
    --name="AdminBridge" ^
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
    echo %~dp0dist\AdminBridge.exe
    echo ========================================================

    echo.
    echo [Assinatura Digital] Assinando dist\AdminBridge.exe com Certificado Authenticode...
    call "%~dp0assinar_executavel.bat" --nopause

    echo Atualizando C:\Utilitario...
    if exist "C:\Utilitario\AdminBridge.exe" (
        attrib -r "C:\Utilitario\AdminBridge.exe" >nul 2>&1
    )
    if exist "C:\Utilitario\AntigravityBridge.exe" (
        attrib -r "C:\Utilitario\AntigravityBridge.exe" >nul 2>&1
    )
    copy /y "%~dp0dist\AdminBridge.exe" "C:\Utilitario\AdminBridge.exe" >nul
    copy /y "%~dp0dist\AdminBridge.exe" "C:\Utilitario\AntigravityBridge.exe" >nul
    echo Executavel copiado para C:\Utilitario com sucesso!
    copy /y "%~dp0instalar_ia_local.bat" "C:\Utilitario\instalar_ia_local.bat" >nul 2>&1

    echo Aplicando blindagem de permissoes NTFS (harden) em C:\Utilitario...
    "C:\Utilitario\AdminBridge.exe" harden

    echo.
    if "%1"=="--with-llm" (
        echo [Instalacao da Mini-IA Local solicitada via argumento]
        call "%~dp0instalar_ia_local.bat" --nopause
    ) else if "%1"=="--install-llm" (
        echo [Instalacao da Mini-IA Local solicitada via argumento]
        call "%~dp0instalar_ia_local.bat" --nopause
    ) else (
        echo [Opcional] A Mini-IA Local pode ser instalada a qualquer momento pelo menu de configuracoes do programa ou via instalar_ia_local.bat.
    )

    echo.
    echo [IMPORTANTE] Se o utilitario ja estava provisionado, abra o painel e clique em 'Corrigir' com sua Senha Mestra para re-ancorar o novo hash do executavel.

    set "DESK_DIR="
    if exist "%USERPROFILE%\OneDrive\Desktop" (
        set "DESK_DIR=%USERPROFILE%\OneDrive\Desktop"
    ) else if exist "%USERPROFILE%\Desktop" (
        set "DESK_DIR=%USERPROFILE%\Desktop"
    )

    if defined DESK_DIR (
        echo Atualizando Area de Trabalho: !DESK_DIR!
        del /f /q "!DESK_DIR!\AntigravityBridge.old.exe" 2>nul
        del /f /q "!DESK_DIR!\Antigravity Bridge.lnk" 2>nul
        del /f /q "!DESK_DIR!\Antigravity Admin Bridge.lnk" 2>nul
        del /f /q "!DESK_DIR!\Configurar Antigravity Bridge.lnk" 2>nul
        del /f /q "!DESK_DIR!\AntigravityBridge.exe" 2>nul
        copy /y "%~dp0dist\AdminBridge.exe" "!DESK_DIR!\AdminBridge.exe" >nul
        copy /y "%~dp0dist\AdminBridge.exe" "!DESK_DIR!\Admin Bridge.exe" >nul

        powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('!DESK_DIR!\Admin Bridge.lnk'); $s.TargetPath = '!DESK_DIR!\AdminBridge.exe'; $s.WorkingDirectory = 'C:\Utilitario'; $s.IconLocation = 'C:\Utilitario\icon.ico,0'; $s.Description = 'Admin Bridge • Central de Gestao e Autorizacao'; $s.Save()" >nul 2>nul
        echo Executavel AdminBridge.exe e atalhos atualizados na Area de Trabalho!
    )
    echo.
    echo Compilacao finalizada com sucesso!
    pause
) else (
    echo.
    echo [ERRO] Falha ao compilar com PyInstaller.
    pause
    exit /b 1
)
pause
