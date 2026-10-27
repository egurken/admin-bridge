@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo Compilando Admin Bridge no repositorio Git
echo Repositorio: %~dp0
echo ========================================================

cd /d "%~dp0"

set "PYTHON_CMD=python"
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    if exist "C:\Users\epgur\AppData\Local\Programs\Python\Python313\python.exe" (
        set "PYTHON_CMD=C:\Users\epgur\AppData\Local\Programs\Python\Python313\python.exe"
    ) else if exist "C:\Program Files\Python313\python.exe" (
        set "PYTHON_CMD=C:\Program Files\Python313\python.exe"
    ) else (
        set "PYTHON_CMD=py"
    )
)

echo.
echo [1/3] Executando testes automatizados de seguranca...
"%PYTHON_CMD%" test_security_rules.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERRO CRITICO] Falha nos testes de seguranca! Compilacao abortada.
    pause
    exit /b 1
)

echo.
echo [2/3] Executando teste ativo de ciclo de vida completo...
"%PYTHON_CMD%" test_full_lifecycle.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERRO CRITICO] Falha no teste ativo do ciclo de vida! Compilacao abortada.
    pause
    exit /b 1
)

echo.
echo [3/3] Gerando executavel standalone (Onefile)...
"%PYTHON_CMD%" -m PyInstaller ^
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
        takeown /f "C:\Utilitario\AdminBridge.exe" /a >nul 2>&1
        icacls "C:\Utilitario\AdminBridge.exe" /grant *S-1-5-32-544:F >nul 2>&1
        attrib -r "C:\Utilitario\AdminBridge.exe" >nul 2>&1
    )
    if exist "C:\Utilitario\AntigravityBridge.exe" (
        takeown /f "C:\Utilitario\AntigravityBridge.exe" /a >nul 2>&1
        icacls "C:\Utilitario\AntigravityBridge.exe" /grant *S-1-5-32-544:F >nul 2>&1
        attrib -r "C:\Utilitario\AntigravityBridge.exe" >nul 2>&1
    )
    copy /y "%~dp0dist\AdminBridge.exe" "C:\Utilitario\AdminBridge.exe" >nul
    copy /y "%~dp0dist\AdminBridge.exe" "C:\Utilitario\AntigravityBridge.exe" >nul
    echo Executavel copiado para C:\Utilitario com sucesso!
    copy /y "%~dp0instalar_ia_local.bat" "C:\Utilitario\instalar_ia_local.bat" >nul 2>&1

    echo Aplicando blindagem de permissoes NTFS (harden) em C:\Utilitario...
    "C:\Utilitario\AdminBridge.exe" harden

    echo Registrando e iniciando servico em segundo plano sob conta SYSTEM...
    "C:\Utilitario\AdminBridge.exe" setup-service

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
