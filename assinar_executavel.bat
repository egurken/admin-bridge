@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo   ASSINATURA DIGITAL AUTHENTICODE - ADMIN BRIDGE
echo ========================================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0assinar_executavel.ps1"
set "SIGN_ERR=%ERRORLEVEL%"

echo.
echo ========================================================
if %SIGN_ERR% EQU 0 (
    echo   Processo de assinatura concluido com sucesso!
) else (
    echo   [AVISO] O processo de assinatura retornou codigo de erro: %SIGN_ERR%
)
echo ========================================================

if "%1" NEQ "--nopause" pause
