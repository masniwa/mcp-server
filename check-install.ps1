param(
    [string]$CphRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'burp-cph'),
    [switch]$DynamicWorkflow
)
$ErrorActionPreference = 'Stop'
$runtime = Join-Path $PSScriptRoot 'runtime'
$checks = [ordered]@{}
foreach ($name in @('build/libs/burp-mcp-all.jar','libs/mcp-proxy-all.jar')) {
    $checks[$name] = Test-Path -LiteralPath (Join-Path $PSScriptRoot $name) -PathType Leaf
}
$java = Get-Command java.exe -ErrorAction SilentlyContinue
$checks['Java 21 or newer on PATH'] = $false
if ($java) {
    $version = (cmd.exe /d /c 'java.exe -version 2>&1') -join ' '
    if ($version -match 'version "(\d+)') {
        $checks['Java 21 or newer on PATH'] = [int]$Matches[1] -ge 21
    }
}
foreach ($name in @('CustomParamHandler_marged_api_v0.2.py','CPH_Managed.py','CPH_API_v0_2.py')) {
    $checks[$name] = Test-Path -LiteralPath (Join-Path $CphRoot $name) -PathType Leaf
}
$connection = Join-Path $CphRoot 'runtime/cph-connection.json'
$checks['CPH points to this MCP runtime'] = $false
if (Test-Path -LiteralPath $connection -PathType Leaf) {
    $value = (Get-Content -LiteralPath $connection -Raw | ConvertFrom-Json).runtimeDirectory
    if ($value) {
        $path = if ([IO.Path]::IsPathRooted($value)) { $value } else { Join-Path (Split-Path -Parent $connection) $value }
        $checks['CPH points to this MCP runtime'] = [IO.Path]::GetFullPath($path) -eq [IO.Path]::GetFullPath($runtime)
    }
}
$settings = Join-Path $runtime 'settings.json'
$checks['MCP has initialized local settings'] = Test-Path -LiteralPath $settings -PathType Leaf
if ($checks['MCP has initialized local settings']) {
    $profile = Get-Content -LiteralPath $settings -Raw | ConvertFrom-Json
    $checks['REVIEW settings'] = $profile.authorizationMode -eq 'REVIEW'
    $required = @('SCANNER_WORKFLOW','EXCLUSIVE_CONTEXT')
    if ($DynamicWorkflow) { $required += 'DYNAMIC_WORKFLOW_VERIFIED' }
    foreach ($capability in $required) {
        $checks["Registered $capability"] = $profile.verifiedCapabilities -ccontains $capability
    }
}
foreach ($check in $checks.GetEnumerator()) {
    $state = if ($check.Value) { 'OK' } else { 'MISSING' }
    Write-Output ("{0,-8} {1}" -f $state,$check.Key)
}
Write-Output 'Live REVIEW mode, CPH connectivity, approvals and native audit status must be checked in Burp.'
if ($checks.Values -contains $false) { exit 1 }
