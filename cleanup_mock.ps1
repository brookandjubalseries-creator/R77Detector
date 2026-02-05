# Clean up mock r77 indicators
$tempPath = [System.IO.Path]::GetTempPath()

Remove-Item -Path (Join-Path $tempPath '$77testfile.dll') -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $tempPath '$77hidden') -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path 'C:\Users\Purge\Desktop\$77rootkit.dll' -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'C:\Users\Purge\Desktop\$77config_backup' -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $env:LOCALAPPDATA '$77cache.dat') -Force -ErrorAction SilentlyContinue

Write-Host "Mock r77 indicators cleaned up!"
