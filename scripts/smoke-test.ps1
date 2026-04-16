param(
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 18080,
    [string]$BinaryPath = (Join-Path $PSScriptRoot "..\\target\\debug\\smtp-analyzer.exe"),
    [string]$SamplePath = (Join-Path $PSScriptRoot "..\\service_test_sample.pcap")
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if (-not (Test-Path -LiteralPath $BinaryPath)) {
    Push-Location $repoRoot
    try {
        cargo build
    }
    finally {
        Pop-Location
    }
}

$binary = (Resolve-Path -LiteralPath $BinaryPath).Path
$sample = (Resolve-Path -LiteralPath $SamplePath).Path
$sampleName = [System.IO.Path]::GetFileName($sample)
$baseUri = "http://$BindHost`:$Port"

$proc = Start-Process `
    -FilePath $binary `
    -ArgumentList @("serve", "--host", $BindHost, "--port", $Port) `
    -WorkingDirectory $repoRoot `
    -PassThru

try {
    $health = $null
    $deadline = (Get-Date).AddSeconds(10)

    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 250

        try {
            $health = Invoke-RestMethod -Uri "$baseUri/health" -TimeoutSec 2
            break
        }
        catch {
            if ($proc.HasExited) {
                throw "smtp-analyzer exited before the health check passed."
            }
        }
    }

    if ($null -eq $health) {
        throw "Timed out waiting for $baseUri/health to become ready."
    }

    if ($health.status -ne "ok") {
        throw "Unexpected health payload: $($health | ConvertTo-Json -Compress)"
    }

    $body = [System.IO.File]::ReadAllBytes($sample)
    $response = Invoke-RestMethod `
        -Uri "$baseUri/analyze-upload" `
        -Method Post `
        -ContentType "application/octet-stream" `
        -Headers @{
            "X-File-Extension" = "pcap"
            "X-File-Name" = $sampleName
            "X-Ports" = "25,587,465"
            "X-Ignore-Vlan" = "1"
        } `
        -Body $body `
        -TimeoutSec 30

    if ($response.packet_count -lt 1) {
        throw "The smoke test response did not include any packets."
    }

    Write-Output "Health check: ok"
    Write-Output ("Analyze upload: ok ({0}, packets={1}, flows={2})" -f $response.file, $response.packet_count, $response.report.summary.total_flows)
    $response | ConvertTo-Json -Depth 8
}
finally {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id
    }
}
