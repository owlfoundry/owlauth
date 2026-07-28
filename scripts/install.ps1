$ErrorActionPreference = "Stop"

$Repository = if ($env:OWLAUTH_GITHUB_REPO) { $env:OWLAUTH_GITHUB_REPO } else { "owlfoundry/owlauth" }
$RequestedVersion = if ($env:OWLAUTH_VERSION) { $env:OWLAUTH_VERSION } else { "latest" }
$InstallDirectory = if ($env:OWLAUTH_INSTALL_DIR) { $env:OWLAUTH_INSTALL_DIR } else { Join-Path $HOME ".local\bin" }
$TemporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("owlauth-install-" + [Guid]::NewGuid().ToString("N"))

function Resolve-Version {
    if ($RequestedVersion -ne "latest") {
        return $RequestedVersion -replace '^cli-v', '' -replace '^v', ''
    }
    $releases = Invoke-RestMethod -Headers @{ "User-Agent" = "owlauth-installer" } -Uri "https://api.github.com/repos/$Repository/releases?per_page=100"
    $release = $releases | Where-Object { -not $_.draft -and -not $_.prerelease -and $_.tag_name -match '^cli-v(.+)$' } | Select-Object -First 1
    if (-not $release) { throw "could not resolve the latest stable CLI release" }
    return $release.tag_name.Substring(5)
}

function Get-Sha256 {
    param([string]$Path)
    $Stream = [System.IO.File]::OpenRead($Path)
    try {
        $Hasher = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($Hasher.ComputeHash($Stream))).Replace("-", "").ToLowerInvariant()
        }
        finally {
            $Hasher.Dispose()
        }
    }
    finally {
        $Stream.Dispose()
    }
}

try {
    $Version = Resolve-Version
    if ($Version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$') {
        throw "version is not valid SemVer: $Version"
    }
    $Tag = "cli-v$Version"
    $Target = "x86_64-pc-windows-msvc"
    if (-not [Environment]::Is64BitOperatingSystem) { throw "only 64-bit Windows is supported" }
    $ArchiveName = "owlauth-cli-$Version-$Target.zip"
    $BaseUrl = "https://github.com/$Repository/releases/download/$Tag"
    New-Item -ItemType Directory -Force -Path $TemporaryDirectory, $InstallDirectory | Out-Null
    $Archive = Join-Path $TemporaryDirectory $ArchiveName
    $ChecksumFile = Join-Path $TemporaryDirectory "SHA256SUMS"
    Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$ArchiveName" -OutFile $Archive
    Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/SHA256SUMS" -OutFile $ChecksumFile
    $ChecksumLine = Get-Content $ChecksumFile | Where-Object { $_ -match "^[0-9a-fA-F]{64}\s+\*?$([Regex]::Escape($ArchiveName))$" } | Select-Object -First 1
    if (-not $ChecksumLine) { throw "SHA256SUMS has no entry for $ArchiveName" }
    $Expected = ($ChecksumLine -split '\s+')[0].ToLowerInvariant()
    $Actual = Get-Sha256 $Archive
    if ($Expected -ne $Actual) { throw "checksum mismatch for $ArchiveName" }
    $Extracted = Join-Path $TemporaryDirectory "extracted"
    Expand-Archive -Path $Archive -DestinationPath $Extracted
    $Source = Join-Path $Extracted "owlauth.exe"
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw "archive is missing owlauth.exe" }
    $Destination = Join-Path $InstallDirectory "owlauth.exe"
    $Staged = "$Destination.new.$PID"
    Copy-Item -LiteralPath $Source -Destination $Staged -Force

    if ($env:OWLAUTH_UPDATER_PID) {
        if (-not $env:OWLAUTH_UPDATE_READY_FILE) { throw "OWLAUTH_UPDATE_READY_FILE is required for self-update" }
        Set-Content -LiteralPath $env:OWLAUTH_UPDATE_READY_FILE -Value "ready" -NoNewline
        $ParentPid = [int]$env:OWLAUTH_UPDATER_PID
        try { Wait-Process -Id $ParentPid -ErrorAction SilentlyContinue } catch { }
    }
    Move-Item -LiteralPath $Staged -Destination $Destination -Force
    Write-Output "installed $Destination from $Tag"
    if ($env:PATH -notlike "*$InstallDirectory*") {
        Write-Output "add $InstallDirectory to PATH"
    }
}
finally {
    Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
