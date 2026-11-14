$dest = "C:\Tools\Sysinternals"
New-Item -ItemType Directory -Path $dest -Force | Out-Null
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile "$env:TEMP\SysinternalsSuite.zip"
Expand-Archive -Path "$env:TEMP\SysinternalsSuite.zip" -DestinationPath $dest -Force
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";$dest", "Machine")
