@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo   ASSINATURA DIGITAL AUTHENTICODE - ADMIN BRIDGE
echo ========================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ErrorActionPreference = 'Stop'; " ^
    "$subject = 'CN=AdminBridge Local Sovereign Root'; " ^
    "$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -eq $subject } | Select-Object -First 1; " ^
    "if (-not $cert) { " ^
    "    Write-Host '[*] Criando Certificado Digital de Assinatura de Codigo (RSA 4096 / SHA256)...' -ForegroundColor Cyan; " ^
    "    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject -KeyAlgorithm RSA -KeyLength 4096 -HashAlgorithm SHA256 -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddYears(10); " ^
    "    try { " ^
    "        $tmpCer = Join-Path $env:TEMP 'adminbridge_root.cer'; " ^
    "        Export-Certificate -Cert $cert -FilePath $tmpCer -Force | Out-Null; " ^
    "        Import-Certificate -FilePath $tmpCer -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null; " ^
    "        Import-Certificate -FilePath $tmpCer -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null; " ^
    "        Remove-Item $tmpCer -Force -ErrorAction SilentlyContinue; " ^
    "        Write-Host '[+] Certificado registrado em Autoridades Raiz e Publicadores Confiaveis da maquina!' -ForegroundColor Green; " ^
    "    } catch { " ^
    "        Write-Host '[AVISO] Execute como Administrador para instalar o certificado na raiz da maquina.' -ForegroundColor Yellow; " ^
    "    } " ^
    "} else { " ^
    "    Write-Host ('[*] Certificado existente localizado: Thumbprint ' + $cert.Thumbprint) -ForegroundColor Cyan; " ^
    "} " ^
    "$targets = @('dist\AdminBridge.exe', 'C:\Utilitario\AdminBridge.exe', 'C:\Utilitario\AntigravityBridge.exe'); " ^
    "foreach ($t in $targets) { " ^
    "    if (Test-Path $t) { " ^
    "        attrib -r $t 2>$null; " ^
    "        $sig = Set-AuthenticodeSignature -FilePath $t -Certificate $cert -HashAlgorithm SHA256; " ^
    "        Write-Host ('[+] Assinado: ' + $t + ' -> Status: ' + $sig.Status) -ForegroundColor Green; " ^
    "    } " ^
    "}"

echo.
echo ========================================================
echo   Processo de assinatura concluido!
echo ========================================================
if "%1" NEQ "--nopause" pause
