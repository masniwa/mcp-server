param([ValidateRange(1,65535)][int]$Port = 9876)
$ErrorActionPreference = 'Stop'
$proxy = Join-Path $PSScriptRoot 'libs/mcp-proxy-all.jar'
if (-not (Test-Path -LiteralPath $proxy -PathType Leaf)) { throw "Missing proxy JAR: $proxy" }
$java = (Get-Command java.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
& $java -jar $proxy --sse-url "http://127.0.0.1:$Port"
exit $LASTEXITCODE
