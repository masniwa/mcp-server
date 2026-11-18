param(
    [string]$CphRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'burp-cph'),
    [string]$McpJar = (Join-Path $PSScriptRoot 'build/libs/burp-mcp-all.jar'),
    [switch]$DynamicWorkflow
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'scripts/RuntimeConnection.ps1')
try {
    $selection = Get-RuntimeSelection -McpJar $McpJar -CphRoot $CphRoot
    $connectionReport = Test-RuntimeConnection $selection
} catch { Write-Output 'MISSING  Runtime selection invalid; run configure-runtime.ps1 with the actual selected JAR and CPH paths.'; exit 1 }
$runtime = $selection.McpRuntime
$checks = [ordered]@{}
foreach ($name in @('build/libs/burp-mcp-all.jar','libs/mcp-proxy-all.jar')) {
    $checks[$name] = Test-Path -LiteralPath (Join-Path $selection.McpRoot $name) -PathType Leaf
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
$checks['CPH points to selected MCP runtime'] = $connectionReport.pairingMatches
$checks['Valid local credential profile'] = $connectionReport.profileState -eq 'READY'
$checks['No legacy MCP credential redirect'] = -not $connectionReport.managedCredentialRedirectPresent
$checks['No launch overrides in this shell (Burp environment still needs checking)'] = -not $connectionReport.launchOverridesPresent
Write-Output ("Selected MCP JAR: {0}" -f $selection.McpJar)
Write-Output ("Expected runtime: {0}" -f $selection.McpRuntime)
Write-Output ("Configured CPH runtime: {0}" -f $connectionReport.configuredRuntime)
$settings = Join-Path $runtime 'settings.json'
$checks['MCP has initialized local settings'] = Test-Path -LiteralPath $settings -PathType Leaf
if ($checks['MCP has initialized local settings']) {
    try { $profile = Read-RuntimeJson $settings }
    catch { Write-Output 'MISSING  Settings JSON invalid; input details withheld.'; exit 1 }
    $checks['REVIEW settings'] = $connectionReport.profileState -eq 'READY'
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
