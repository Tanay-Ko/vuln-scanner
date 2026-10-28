$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$binDirectory = Join-Path $projectRoot 'bin'
$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) (
    'vuln-scanner-tools-' + [guid]::NewGuid().ToString('N')
)

function Install-VerifiedReleaseBinary {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$ArchivePattern,
        [Parameter(Mandatory = $true)][string]$ExecutableName
    )

    $release = Invoke-RestMethod `
        -Uri "https://api.github.com/repos/$Repository/releases/latest" `
        -Headers @{ 'User-Agent' = 'VulnScanner-local-tool-installer'; Accept = 'application/vnd.github+json' }
    $archiveAsset = $release.assets |
        Where-Object { $_.name -match $ArchivePattern } |
        Select-Object -First 1
    $checksumAsset = $release.assets |
        Where-Object { $_.name -match 'checksums\.txt$' } |
        Select-Object -First 1

    if (-not $archiveAsset -or -not $checksumAsset) {
        throw "Could not find a Windows archive and checksum in $Repository release $($release.tag_name)."
    }

    $toolDirectory = Join-Path $temporaryDirectory ([System.IO.Path]::GetFileNameWithoutExtension($archiveAsset.name))
    New-Item -ItemType Directory -Path $toolDirectory -Force | Out-Null
    $archivePath = Join-Path $toolDirectory $archiveAsset.name
    $checksumsPath = Join-Path $toolDirectory $checksumAsset.name

    Invoke-RestMethod -Uri $archiveAsset.browser_download_url -OutFile $archivePath
    Invoke-RestMethod -Uri $checksumAsset.browser_download_url -OutFile $checksumsPath

    $checksumPattern = '^\s*([a-fA-F0-9]{64})\s+\*?' + [regex]::Escape($archiveAsset.name) + '\s*$'
    $checksumLine = Get-Content -LiteralPath $checksumsPath |
        Where-Object { $_ -match $checksumPattern } |
        Select-Object -First 1
    if (-not $checksumLine -or $checksumLine -notmatch $checksumPattern) {
        throw "No SHA-256 checksum for $($archiveAsset.name) was published in the release."
    }

    $expectedHash = $Matches[1].ToLowerInvariant()
    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "SHA-256 verification failed for $($archiveAsset.name)."
    }

    $extractDirectory = Join-Path $toolDirectory 'extracted'
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDirectory -Force
    $binary = Get-ChildItem -LiteralPath $extractDirectory -Filter $ExecutableName -File -Recurse |
        Select-Object -First 1
    if (-not $binary) {
        throw "$ExecutableName was not present in $($archiveAsset.name)."
    }

    $destination = Join-Path $binDirectory $ExecutableName
    Copy-Item -LiteralPath $binary.FullName -Destination $destination -Force
    Write-Output "Installed $ExecutableName from $Repository $($release.tag_name) (SHA-256 verified)."
}

try {
    New-Item -ItemType Directory -Path $binDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $temporaryDirectory -Force | Out-Null

    Install-VerifiedReleaseBinary `
        -Repository 'gitleaks/gitleaks' `
        -ArchivePattern '^gitleaks_.*_windows_x64\.zip$' `
        -ExecutableName 'gitleaks.exe'
    Install-VerifiedReleaseBinary `
        -Repository 'aquasecurity/trivy' `
        -ArchivePattern '^trivy_.*_windows-64bit\.zip$' `
        -ExecutableName 'trivy.exe'

    & (Join-Path $binDirectory 'gitleaks.exe') version
    if ($LASTEXITCODE -ne 0) {
        throw 'Gitleaks was installed but its version check failed.'
    }
    & (Join-Path $binDirectory 'trivy.exe') --version
    if ($LASTEXITCODE -ne 0) {
        throw 'Trivy was installed but its version check failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
