# Clean up all mock r77 files
$searchPaths = @(
    $env:TEMP,
    $env:LOCALAPPDATA,
    $env:APPDATA,
    "C:\Users\Purge\Desktop"
)

Write-Host "Searching for remaining mock files..." -ForegroundColor Cyan

$found = $false
foreach ($path in $searchPaths) {
    if (Test-Path $path) {
        # Find $77 prefixed items
        Get-ChildItem -Path $path -Filter '*$77*' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "  Removing: $($_.FullName)" -ForegroundColor Yellow
            Remove-Item $_.FullName -Force -Recurse -ErrorAction SilentlyContinue
            $found = $true
        }

        # Find r77 prefixed items
        Get-ChildItem -Path $path -Filter 'r77-*' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "  Removing: $($_.FullName)" -ForegroundColor Yellow
            Remove-Item $_.FullName -Force -Recurse -ErrorAction SilentlyContinue
            $found = $true
        }

        # Find .shellcode files
        Get-ChildItem -Path $path -Filter '*.shellcode' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "  Removing: $($_.FullName)" -ForegroundColor Yellow
            Remove-Item $_.FullName -Force -Recurse -ErrorAction SilentlyContinue
            $found = $true
        }
    }
}

# Clean registry
Write-Host "`nCleaning registry..." -ForegroundColor Cyan
try {
    Remove-Item -Path "HKCU:\SOFTWARE\`$77config" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  Removed HKCU\SOFTWARE\`$77config" -ForegroundColor Yellow
} catch {}

# Clean DeepScan quarantine
$quarantinePath = Join-Path $env:LOCALAPPDATA "DeepScan\Quarantine"
if (Test-Path $quarantinePath) {
    Write-Host "`nClearing quarantine folder..." -ForegroundColor Cyan
    Remove-Item "$quarantinePath\*" -Force -Recurse -ErrorAction SilentlyContinue
    Write-Host "  Cleared: $quarantinePath" -ForegroundColor Yellow
}

if (-not $found) {
    Write-Host "`nNo mock files found - already clean!" -ForegroundColor Green
} else {
    Write-Host "`nCleanup complete!" -ForegroundColor Green
}
