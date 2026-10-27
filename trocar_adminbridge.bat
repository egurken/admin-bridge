@echo off
rem Script de Substituicao e Atualizacao Direta do Admin Bridge para C:\Utilitario
title Atualizador do Admin Bridge

rem 1. Copia binario e helper para TEMP para evitar problemas de codepage com acentos
if exist "%~dp0dist\AdminBridge.exe" copy /y "%~dp0dist\AdminBridge.exe" "%TEMP%\AdminBridge_novo.exe" >nul 2>&1
copy /y "%~f0" "%TEMP%\trocar.bat" >nul 2>&1

rem 2. Verifica se possui privilegios administrativos
net session >nul 2>&1
if "%errorlevel%"=="0" goto :is_admin

echo [*] Solicitando elevacao administrativa para substituir o executavel...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/k \"\"%TEMP%\trocar.bat\"\"' -Verb RunAs"
exit /b 0

:is_admin
echo ========================================================
echo        ATUALIZACAO DIRETA DO ADMIN BRIDGE
echo ========================================================
echo.

set "DIST_EXE=%~dp0dist\AdminBridge.exe"
if not exist "%DIST_EXE%" (
    if exist "%TEMP%\AdminBridge_novo.exe" (
        set "DIST_EXE=%TEMP%\AdminBridge_novo.exe"
    ) else if exist "c:\Users\epgur\.gemini\antigravity\Utilitário\dist\AdminBridge.exe" (
        set "DIST_EXE=c:\Users\epgur\.gemini\antigravity\Utilitário\dist\AdminBridge.exe"
    )
)
set "DEST_DIR=C:\Utilitario"
set "DEST_EXE=C:\Utilitario\AdminBridge.exe"
set "SIGN_SCRIPT=%~dp0assinar_executavel.ps1"
if not exist "%SIGN_SCRIPT%" (
    if exist "c:\Users\epgur\.gemini\antigravity\Utilitário\assinar_executavel.ps1" (
        set "SIGN_SCRIPT=c:\Users\epgur\.gemini\antigravity\Utilitário\assinar_executavel.ps1"
    )
)

if not exist "%DIST_EXE%" goto :err_no_dist

echo [*] 1. Interrompendo tarefas agendadas e processos do daemon...
schtasks /end /tn AdminBridge >nul 2>&1
schtasks /end /tn AdminBridgeWatchdog >nul 2>&1
taskkill /f /im AdminBridge.exe >nul 2>&1
timeout /t 2 /nobreak >nul

echo [*] 2. Removendo atributos de protecao de gravacao...
attrib -r "%DEST_EXE%" 2>nul

echo [*] 3. Substituindo binario em C:\Utilitario...
copy /y "%DIST_EXE%" "%DEST_EXE%"
if errorlevel 1 goto :err_copy

echo [*] 4. Atualizando executavel na Area de Trabalho...
if exist "%USERPROFILE%\OneDrive\Desktop" copy /y "%DIST_EXE%" "%USERPROFILE%\OneDrive\Desktop\AdminBridge.exe" >nul 2>&1
if exist "%USERPROFILE%\Desktop" copy /y "%DIST_EXE%" "%USERPROFILE%\Desktop\AdminBridge.exe" >nul 2>&1

echo [*] 5. Aplicando assinatura digital Authenticode...
powershell -NoProfile -ExecutionPolicy Bypass -File "%SIGN_SCRIPT%"

echo [*] 6. Reiniciando servico de segundo plano...
schtasks /run /tn AdminBridge >nul 2>&1

echo.
echo ========================================================
echo [+] ADMIN BRIDGE ATUALIZADO COM SUCESSO EM C:\UTILITARIO!
echo ========================================================
echo.
pause
exit /b 0

:err_no_dist
echo [ERRO] O binario compilado dist\AdminBridge.exe nao foi encontrado!
echo Execute a compilacao antes de executar a troca.
echo.
pause
exit /b 1

:err_copy
echo [ERRO] Nao foi possivel copiar o executavel para C:\Utilitario!
echo Verifique se ha processos bloqueando o arquivo.
echo.
pause
exit /b 1
