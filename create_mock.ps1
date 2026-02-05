# Create mock r77 indicators for testing the detector
$tempPath = [System.IO.Path]::GetTempPath()

# Create mock files
New-Item -Path (Join-Path $tempPath '$77testfile.dll') -ItemType File -Force
New-Item -Path (Join-Path $tempPath '$77hidden') -ItemType Directory -Force
New-Item -Path 'C:\Users\Purge\Desktop\$77rootkit.dll' -ItemType File -Force
New-Item -Path 'C:\Users\Purge\Desktop\$77config_backup' -ItemType Directory -Force
New-Item -Path (Join-Path $env:LOCALAPPDATA '$77cache.dat') -ItemType File -Force

Write-Host "Mock r77 indicators created successfully!"
