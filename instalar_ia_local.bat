@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo   ATIVANDO E TESTANDO MINI-IA LOCAL (QWEN 2.5 - 0.5B)
echo   Download direto via API Local do Ollama (127.0.0.1:11434)
echo ========================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ErrorActionPreference = 'Continue'; " ^
    "try { " ^
    "    $tags = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -Method Get -TimeoutSec 2; " ^
    "    Write-Host '[*] Servidor Ollama detectado em http://127.0.0.1:11434!' -ForegroundColor Cyan; " ^
    "} catch { " ^
    "    $ollamaExe = Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe'; " ^
    "    if (Test-Path $ollamaExe) { " ^
    "        Write-Host '[*] Iniciando servidor Ollama local...' -ForegroundColor Cyan; " ^
    "        Start-Process -FilePath $ollamaExe -ArgumentList 'serve' -WindowStyle Hidden; " ^
    "        Start-Sleep -Seconds 2; " ^
    "    } " ^
    "} " ^
    "Write-Host '[*] Baixando modelo ultraleve qwen2.5:0.5b (~350 MB) via API HTTP do Ollama...' -ForegroundColor Yellow; " ^
    "try { " ^
    "    $res = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/pull' -Method Post -ContentType 'application/json' -Body '{\"name\":\"qwen2.5:0.5b\",\"stream\":false}' -TimeoutSec 600; " ^
    "    Write-Host '[+] Modelo qwen2.5:0.5b baixado com sucesso!' -ForegroundColor Green; " ^
    "    Write-Host '[*] Realizando teste de verificacao e liberando RAM (keep_alive=0s)...' -ForegroundColor Cyan; " ^
    "    $testBody = '{\"model\":\"qwen2.5:0.5b\",\"prompt\":\"Responda apenas OK\",\"stream\":false,\"keep_alive\":\"0s\"}'; " ^
    "    $testRes = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/generate' -Method Post -ContentType 'application/json' -Body $testBody -TimeoutSec 30; " ^
    "    New-Item -ItemType Directory -Force -Path 'C:\Utilitario\queue' | Out-Null; " ^
    "    Set-Content -Path 'C:\Utilitario\queue\ai_ready.json' -Value '{\"verified\":true,\"model\":\"qwen2.5:0.5b\"}' -Encoding UTF8; " ^
    "    Write-Host '[SUCESSO] Mini-IA testada, validada e pronta (0 MB na RAM em repouso)!' -ForegroundColor Green; " ^
    "} catch { " ^
    "    Write-Host ('[AVISO] Nao foi possivel conectar ao Ollama em 127.0.0.1:11434: ' + $_.Exception.Message) -ForegroundColor Yellow; " ^
    "}"

if "%1" NEQ "--nopause" pause
