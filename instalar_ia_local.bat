@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo   INSTALADOR AUTOMATICO DA MINI-IA LOCAL (QWEN 0.5B)
echo   Otimizado para Intel Core i5 (Apenas ~350 MB)
echo ========================================================
echo.

where ollama >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    if exist "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" (
        set "PATH=%PATH%;%LOCALAPPDATA%\Programs\Ollama"
    )
)

where ollama >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [*] Motor Ollama nao encontrado. Instalando automaticamente...
    where winget >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        winget install --id Ollama.Ollama -e --silent --accept-package-agreements --accept-source-agreements
    ) else (
        echo [*] Baixando instalador oficial do Ollama via PowerShell...
        powershell -NoProfile -ExecutionPolicy Bypass -Command ^
            "$url = 'https://ollama.com/download/OllamaSetup.exe'; " ^
            "$out = Join-Path $env:TEMP 'OllamaSetup.exe'; " ^
            "Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing; " ^
            "Start-Process -FilePath $out -ArgumentList '/VERYSILENT /NORESTART' -Wait"
    )
    set "PATH=%PATH%;%LOCALAPPDATA%\Programs\Ollama"
)

where ollama >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [AVISO] Nao foi possivel localizar o executavel do Ollama automaticamente.
    echo O Admin Bridge continuara usando o Explicador Semantico Embarcado (0 MB) normalmente!
    if "%1" NEQ "--nopause" pause
    exit /b 0
)

echo.
echo [*] Iniciando motor local em segundo plano para baixar o mini-modelo qwen2.5:0.5b (~350 MB)...
start "" /b ollama serve >nul 2>&1
timeout /t 2 /nobreak >nul

echo [*] Baixando modelo ultraleve qwen2.5:0.5b (Roda em CPU Core i5 com keep_alive=0s)...
ollama pull qwen2.5:0.5b

echo.
echo ========================================================
echo   [SUCESSO] Mini-IA Local (qwen2.5:0.5b) pronta!
echo   NOTA: O modelo fica com 0 MB na RAM em repouso e so
echo   carrega por 1 segundo quando um script suspeito surgir!
echo ========================================================
if "%1" NEQ "--nopause" pause
