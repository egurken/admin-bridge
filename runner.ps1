param (
    [Parameter(Mandatory=$true)]
    [string]$ScriptPath,
    [Parameter(Mandatory=$true)]
    [string]$ScriptType,
    [Parameter(Mandatory=$true)]
    [string]$LogPath,
    [Parameter(Mandatory=$true)]
    [string]$ExitPath
)

$exitCode = 0
try {
    if ($ScriptType -eq "bat" -or $ScriptType -eq "cmd") {
        $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$ScriptPath`"" -NoNewWindow -Wait -PassThru -RedirectStandardOutput $LogPath -RedirectStandardError "$LogPath.err"
        $exitCode = $process.ExitCode
        if (Test-Path "$LogPath.err") {
            $errContent = Get-Content "$LogPath.err" -Raw
            if ($errContent) {
                Add-Content -Path $LogPath -Value "`n[STDERR]:`n$errContent"
            }
            Remove-Item "$LogPath.err" -Force -ErrorAction SilentlyContinue
        }
    } else {
        # PowerShell script execution
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`"" -NoNewWindow -Wait -PassThru -RedirectStandardOutput $LogPath -RedirectStandardError "$LogPath.err"
        $exitCode = $process.ExitCode
        if (Test-Path "$LogPath.err") {
            $errContent = Get-Content "$LogPath.err" -Raw
            if ($errContent) {
                Add-Content -Path $LogPath -Value "`n[STDERR]:`n$errContent"
            }
            Remove-Item "$LogPath.err" -Force -ErrorAction SilentlyContinue
        }
    }
} catch {
    $exitCode = 1
    Set-Content -Path $LogPath -Value "Erro ao executar runner: $_"
}

Set-Content -Path $ExitPath -Value $exitCode -Encoding ascii
