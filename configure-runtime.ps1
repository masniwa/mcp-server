[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$McpJar = (Join-Path $PSScriptRoot 'build/libs/burp-mcp-all.jar'),
    [Parameter(Mandatory = $true)][string]$CphRoot,
    [switch]$Configure,
    [switch]$BurpStopped,
    [string]$BackupDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'temp/runtime-connection')
)
# Offline pairing only. Never initializes, copies, changes or prints credentials,
# settings, capabilities, job stores or the running Burp process.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'scripts/RuntimeConnection.ps1')
try {
    $selection = Get-RuntimeSelection -McpJar $McpJar -CphRoot $CphRoot
    if ($Configure) {
        if ($PSCmdlet.ShouldProcess($selection.ConnectionFile, "Pair CPH with $($selection.McpRuntime)")) {
            if (-not $BurpStopped) { throw 'BURP_STOPPED_CONFIRMATION_REQUIRED' }
            Assert-RuntimeMaintenance
            Set-RuntimeConnection -Selection $selection -BackupDirectory $BackupDirectory
        }
    }
    $report = Test-RuntimeConnection -Selection $selection
    $report | ConvertTo-Json -Depth 8
    if (-not $report.pairingMatches) { exit 1 }
    if ($report.profileState -in @('INVALID','PARTIAL','NOT_REVIEW')) { exit 1 }
    if ($report.managedCredentialRedirectPresent) { exit 1 }
    if ($report.launchOverridesPresent) { exit 2 }
} catch {
    # JSON parse exceptions can quote input, including secrets. Report codes only.
    $code = if ($_.Exception.Message -cmatch '^[A-Z][A-Z0-9_]+$') { $_.Exception.Message } else { 'RUNTIME_CONNECTION_CHECK_FAILED' }
    [ordered]@{ success = $false; code = $code } | ConvertTo-Json
    exit 1
}
