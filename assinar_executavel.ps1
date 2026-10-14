# Script de Assinatura Digital Authenticode para o Admin Bridge
$ErrorActionPreference = 'Stop'
$subject = 'CN=AdminBridge Local Sovereign Root'
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -eq $subject } | Select-Object -First 1

if (-not $cert) {
    Write-Host '[*] Criando Certificado Digital de Assinatura de Codigo [RSA 4096 / SHA256]...' -ForegroundColor Cyan
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject -KeyAlgorithm RSA -KeyLength 4096 -HashAlgorithm SHA256 -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddYears(10)
    try {
        $tmpCer = Join-Path $env:TEMP 'adminbridge_root.cer'
        Export-Certificate -Cert $cert -FilePath $tmpCer -Force | Out-Null
        Import-Certificate -FilePath $tmpCer -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
        Import-Certificate -FilePath $tmpCer -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null
        Remove-Item $tmpCer -Force -ErrorAction SilentlyContinue
        Write-Host '[+] Certificado registrado em Autoridades Raiz e Publicadores Confiaveis da maquina!' -ForegroundColor Green
    } catch {
        # Se nao estiver elevado, o certificado assina no nivel de usuario sem interrupcoes
    }
} else {
    Write-Host ('[*] Certificado existente localizado: Thumbprint ' + $cert.Thumbprint) -ForegroundColor Cyan
}

$baseDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$distExe = Join-Path $baseDir 'dist\AdminBridge.exe'

# Se o binario dist\AdminBridge.exe existir, atualiza C:\Utilitario e Area de Trabalho
if (Test-Path $distExe) {
    # 1. Atualiza C:\Utilitario se acessivel
    if (Test-Path 'C:\Utilitario') {
        try {
            attrib -r 'C:\Utilitario\AdminBridge.exe' 2>$null
            attrib -r 'C:\Utilitario\AntigravityBridge.exe' 2>$null
            Copy-Item -Path $distExe -Destination 'C:\Utilitario\AdminBridge.exe' -Force -ErrorAction Stop
            Copy-Item -Path $distExe -Destination 'C:\Utilitario\AntigravityBridge.exe' -Force -ErrorAction Stop
        } catch {
            Write-Host ('[AVISO] Nao foi possivel sobrescrever C:\Utilitario sem elevacao administrativa: ' + $_.Exception.Message) -ForegroundColor Yellow
        }
    }

    # 2. Atualiza Area de Trabalho limpando versoes antigas e mantendo apenas AdminBridge.exe
    $desktopDirs = @(
        (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:USERPROFILE 'OneDrive\Desktop')
    )
    foreach ($d in $desktopDirs) {
        if (Test-Path $d) {
            # Limpa versoes antigas e atalhos legados
            Remove-Item -Path (Join-Path $d 'AdminBridge_Debug.exe') -Force -ErrorAction SilentlyContinue
            Remove-Item -Path (Join-Path $d 'AdminBridge_Release.exe') -Force -ErrorAction SilentlyContinue
            Remove-Item -Path (Join-Path $d 'Admin Bridge.exe') -Force -ErrorAction SilentlyContinue
            Remove-Item -Path (Join-Path $d 'AntigravityBridge.old.exe') -Force -ErrorAction SilentlyContinue
            Remove-Item -Path (Join-Path $d 'AntigravityBridge.exe') -Force -ErrorAction SilentlyContinue
            Remove-Item -Path (Join-Path $d 'Admin Bridge.lnk') -Force -ErrorAction SilentlyContinue
            Remove-Item -Path (Join-Path $d 'Antigravity Bridge.lnk') -Force -ErrorAction SilentlyContinue
            Remove-Item -Path (Join-Path $d 'Antigravity Admin Bridge.lnk') -Force -ErrorAction SilentlyContinue
            Remove-Item -Path (Join-Path $d 'Configurar Antigravity Bridge.lnk') -Force -ErrorAction SilentlyContinue

            attrib -r (Join-Path $d 'AdminBridge.exe') 2>$null
            Copy-Item -Path $distExe -Destination (Join-Path $d 'AdminBridge.exe') -Force -ErrorAction SilentlyContinue
        }
    }
}

$targets = @(
    $distExe,
    'C:\Utilitario\AdminBridge.exe',
    'C:\Utilitario\AntigravityBridge.exe'
)

$desktopDirs = @(
    (Join-Path $env:USERPROFILE 'Desktop'),
    (Join-Path $env:USERPROFILE 'OneDrive\Desktop')
)
foreach ($d in $desktopDirs) {
    if (Test-Path $d) {
        $targets += (Join-Path $d 'AdminBridge.exe')
    }
}

foreach ($t in $targets) {
    if (Test-Path $t) {
        try {
            attrib -r $t 2>$null
            $sig = Set-AuthenticodeSignature -FilePath $t -Certificate $cert -HashAlgorithm SHA256 -ErrorAction Stop
            Write-Host ('[+] Assinado: ' + $t + ' -> Status: ' + $sig.Status) -ForegroundColor Green
        } catch {
            Write-Host ('[AVISO] Nao foi possivel assinar ' + $t + ': ' + $_.Exception.Message) -ForegroundColor Yellow
        }
    }
}

