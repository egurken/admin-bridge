@echo off
chcp 65001 >nul
title Exclusao Total de C:\Utilitario

net session >nul 2>&1
if "%errorlevel%"=="0" goto :is_admin

echo [*] Solicitando permissao de Administrador para exclusao total...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/k \"\"%~f0\"\"' -Verb RunAs"
exit /b 0

:is_admin
echo ========================================================
echo        EXPURGO E EXCLUSAO TOTAL DE C:\UTILITARIO
echo ========================================================
echo.

echo [*] 1. Interrompendo e desregistrando tarefas agendadas...
schtasks /end /tn AdminBridge >nul 2>&1
schtasks /delete /tn AdminBridge /f >nul 2>&1
schtasks /end /tn AdminBridgeWatchdog >nul 2>&1
schtasks /delete /tn AdminBridgeWatchdog /f >nul 2>&1

echo [*] 2. Encerrando processos do Admin Bridge...
taskkill /f /im AdminBridge.exe >nul 2>&1
timeout /t 2 /nobreak >nul

if not exist "C:\Utilitario" goto :not_found

echo [*] 3. Assumindo a posse de todos os arquivos e pastas...
takeown /f "C:\Utilitario" /a /r /d y >nul 2>&1

echo [*] 4. Redefinindo permissoes NTFS e liberando controle total...
icacls "C:\Utilitario" /reset /t /c /q >nul 2>&1
icacls "C:\Utilitario" /grant *S-1-5-32-544:F /t /c /q >nul 2>&1

echo [*] 5. Removendo atributos de sistema e somente-leitura...
attrib -r -s -h "C:\Utilitario\*" /s /d >nul 2>&1

echo [*] 6. Excluindo a pasta C:\Utilitario em definitivo...
rmdir /s /q "C:\Utilitario"
if errorlevel 1 goto :err_rmdir

echo [*] 7. Limpando atalhos e binarios da Area de Trabalho...
if exist "%USERPROFILE%\OneDrive\Desktop\AdminBridge.exe" attrib -r "%USERPROFILE%\OneDrive\Desktop\AdminBridge.exe" >nul 2>&1
if exist "%USERPROFILE%\OneDrive\Desktop\AdminBridge.exe" del /f /q "%USERPROFILE%\OneDrive\Desktop\AdminBridge.exe" >nul 2>&1
if exist "%USERPROFILE%\Desktop\AdminBridge.exe" attrib -r "%USERPROFILE%\Desktop\AdminBridge.exe" >nul 2>&1
if exist "%USERPROFILE%\Desktop\AdminBridge.exe" del /f /q "%USERPROFILE%\Desktop\AdminBridge.exe" >nul 2>&1

echo.
echo ========================================================
echo [+] SUCESSO: A PASTA C:\UTILITARIO FOI EXCLUIDA COM TUDO!
echo ========================================================
echo.
pause
exit /b 0

:not_found
echo [AVISO] A pasta C:\Utilitario ja nao existe no sistema.
echo.
pause
exit /b 0

:err_rmdir
echo [ERRO] Nao foi possivel apagar a pasta C:\Utilitario completamente.
echo Verifique se ha processos abertos ou reinicie o sistema e tente novamente.
echo.
pause
exit /b 1
