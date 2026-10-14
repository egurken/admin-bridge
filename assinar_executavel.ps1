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
        attrib -r 'C:\Utilitario\AdminBridge.exe' 2>$null
        attrib -r 'C:\Utilitario\AntigravityBridge.exe' 2>$null
        Copy-Item -Path $distExe -Destination 'C:\Utilitario\AdminBridge.exe' -Force -ErrorAction SilentlyContinue
        Copy-Item -Path $distExe -Destination 'C:\Utilitario\AntigravityBridge.exe' -Force -ErrorAction SilentlyContinue
    }

    # 2. Atualiza Area de Trabalho
    $desktopDirs = @(
        (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:USERPROFILE 'OneDrive\Desktop')
    )
    foreach ($d in $desktopDirs) {
        if (Test-Path $d) {
            attrib -r (Join-Path $d 'AdminBridge.exe') 2>$null
            attrib -r (Join-Path $d 'Admin Bridge.exe') 2>$null
            Copy-Item -Path $distExe -Destination (Join-Path $d 'AdminBridge.exe') -Force -ErrorAction SilentlyContinue
            Copy-Item -Path $distExe -Destination (Join-Path $d 'Admin Bridge.exe') -Force -ErrorAction SilentlyContinue
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
        $targets += (Join-Path $d 'Admin Bridge.exe')
    }
}

foreach ($t in $targets) {
    if (Test-Path $t) {
        attrib -r $t 2>$null
        $sig = Set-AuthenticodeSignature -FilePath $t -Certificate $cert -HashAlgorithm SHA256
        Write-Host ('[+] Assinado: ' + $t + ' -> Status: ' + $sig.Status) -ForegroundColor Green
    }
}
