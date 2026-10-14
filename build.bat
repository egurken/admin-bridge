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

    for %%D in ("%USERPROFILE%\Desktop" "%USERPROFILE%\OneDrive\Desktop") do (
        if exist "%%~D" (
            echo Limpando versoes antigas da Area de Trabalho em %%~D...
            del /f /q "%%~D\AdminBridge_Debug.exe" 2>nul
            del /f /q "%%~D\AdminBridge_Release.exe" 2>nul
            del /f /q "%%~D\Admin Bridge.exe" 2>nul
            del /f /q "%%~D\AntigravityBridge.old.exe" 2>nul
            del /f /q "%%~D\AntigravityBridge.exe" 2>nul
            del /f /q "%%~D\Antigravity Bridge.lnk" 2>nul
            del /f /q "%%~D\Antigravity Admin Bridge.lnk" 2>nul
            del /f /q "%%~D\Configurar Antigravity Bridge.lnk" 2>nul
            del /f /q "%%~D\Admin Bridge.lnk" 2>nul
            copy /y "%~dp0dist\AdminBridge.exe" "%%~D\AdminBridge.exe" >nul
            echo Disponibilizado apenas AdminBridge.exe em %%~D
        )
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
