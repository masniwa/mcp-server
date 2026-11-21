function Get-RuntimeFullPath([string]$Path) {
    return [IO.Path]::GetFullPath($Path)
}

function Assert-RuntimePlainPath([string]$Path) {
    $part = Get-RuntimeFullPath $Path
    while ($part) {
        if (Test-Path -LiteralPath $part) {
            if ((Get-Item -LiteralPath $part -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'RUNTIME_REPARSE_PATH_UNSUPPORTED'
            }
        }
        $next = Split-Path -Parent $part
        if ($next -eq $part) { break }
        $part = $next
    }
}

function Read-RuntimeJson([string]$Path) {
    try {
        return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop)
    } catch { throw 'RUNTIME_JSON_INVALID' }
}

function Get-RuntimeSelection([string]$McpJar, [string]$CphRoot) {
    $jar = Get-RuntimeFullPath $McpJar
    $cph = Get-RuntimeFullPath $CphRoot
    Assert-RuntimePlainPath $jar
    Assert-RuntimePlainPath $cph
    if (-not (Test-Path -LiteralPath $jar -PathType Leaf)) { throw 'SELECTED_MCP_JAR_MISSING' }
    $parent = Split-Path -Parent $jar
    $build = Split-Path -Parent $parent
    $root = if ((Split-Path -Leaf $parent) -ceq 'libs' -and (Split-Path -Leaf $build) -ceq 'build') {
        Split-Path -Parent $build
    } else { $parent }
    # Use the actual selected JAR, not a guessed sibling named mcp-server.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    try {
        $archive = [IO.Compression.ZipFile]::OpenRead($jar)
        try {
            $entry = $archive.GetEntry('diagnostic-profile.properties')
            if (-not $entry) { throw 'SELECTED_MCP_REVIEW_PROFILE_REQUIRED' }
            $reader = New-Object IO.StreamReader($entry.Open())
            try { $profile = $reader.ReadToEnd() } finally { $reader.Dispose() }
            if ($profile -cnotmatch '(?m)^authorizationMode=REVIEW\s*$') { throw 'SELECTED_MCP_REVIEW_PROFILE_REQUIRED' }
        } finally { $archive.Dispose() }
    } catch {
        if ($_.Exception.Message -eq 'SELECTED_MCP_REVIEW_PROFILE_REQUIRED') { throw }
        throw 'SELECTED_MCP_JAR_INVALID'
    }
    foreach ($name in @('CustomParamHandler_marged_api_v0.2.py','CPH_Managed.py','CPH_API_v0_2.py')) {
        if (-not (Test-Path -LiteralPath (Join-Path $cph $name) -PathType Leaf)) { throw 'SELECTED_CPH_FILES_MISSING' }
        Assert-RuntimePlainPath (Join-Path $cph $name)
    }
    $runtime = Join-Path $root 'runtime'
    $connection = Join-Path $cph 'runtime/cph-connection.json'
    Assert-RuntimePlainPath $runtime
    Assert-RuntimePlainPath $connection
    return [pscustomobject]@{ McpJar=$jar; McpRoot=$root; McpRuntime=$runtime; CphRoot=$cph; ConnectionFile=$connection }
}

function Get-RuntimeReference([string]$FromDirectory, [string]$ToDirectory) {
    $from = [Uri]((Get-RuntimeFullPath $FromDirectory).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar)
    $to = [Uri](Get-RuntimeFullPath $ToDirectory)
    $relative = $from.MakeRelativeUri($to)
    if ($relative.IsAbsoluteUri) { return Get-RuntimeFullPath $ToDirectory }
    return [Uri]::UnescapeDataString($relative.ToString()).Replace('\','/')
}

function Test-RuntimeConnection($Selection) {
    $resolved = $null
    $connectionState = 'MISSING'
    if (Test-Path -LiteralPath $Selection.ConnectionFile -PathType Leaf) {
        try {
            $connection = Read-RuntimeJson $Selection.ConnectionFile
            $value = $connection.runtimeDirectory
            if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) { throw 'RUNTIME_REFERENCE_INVALID' }
            $resolved = if ([IO.Path]::IsPathRooted($value)) { Get-RuntimeFullPath $value } else {
                Get-RuntimeFullPath (Join-Path (Split-Path -Parent $Selection.ConnectionFile) $value)
            }
            Assert-RuntimePlainPath $resolved
            $connectionState = 'VALID'
        } catch { $connectionState = 'INVALID' }
    }
    $runtime = $Selection.McpRuntime
    $profile = 'NOT_INITIALIZED'
    $settingsFile = Join-Path $runtime 'settings.json'
    $secretsFile = Join-Path $runtime 'operator-secrets.json'
    $settingsExists = Test-Path -LiteralPath $settingsFile -PathType Leaf
    $secretsExist = Test-Path -LiteralPath $secretsFile -PathType Leaf
    if ($settingsExists -or $secretsExist) {
        $profile = 'PARTIAL'
        if ($settingsExists -and $secretsExist) {
            try {
                Assert-RuntimePlainPath $settingsFile
                Assert-RuntimePlainPath $secretsFile
                $settings = Read-RuntimeJson $settingsFile
                $secrets = Read-RuntimeJson $secretsFile
                if ($settings.schemaVersion -ne 1 -or $secrets.cph -isnot [string] -or $secrets.worker -isnot [string] -or
                    $secrets.cph.Length -lt 32 -or $secrets.worker.Length -lt 32 -or $secrets.cph -ceq $secrets.worker) {
                    throw 'RUNTIME_PROFILE_INVALID'
                }
                $mode = if ($settings.PSObject.Properties.Name -contains 'authorizationMode') { $settings.authorizationMode } else { 'REVIEW' }
                $profile = if ($mode -ceq 'REVIEW') { 'READY' } else { 'NOT_REVIEW' }
            } catch { $profile = 'INVALID' }
            finally { $secrets = $null }
        }
    }
    $overrideNames = @(Get-ChildItem Env: | Where-Object { $_.Name -like 'BURP_DIAG_*' } | ForEach-Object { $_.Name })
    $legacyRedirect = Test-Path -LiteralPath (Join-Path $runtime 'cph-connection.json')
    $matches = $connectionState -eq 'VALID' -and $resolved -eq (Get-RuntimeFullPath $runtime)
    return [ordered]@{
        success = $matches -and $profile -in @('READY','NOT_INITIALIZED') -and $overrideNames.Count -eq 0 -and -not $legacyRedirect
        mcpJar = $Selection.McpJar
        expectedRuntime = $runtime
        cphRoot = $Selection.CphRoot
        connectionFile = $Selection.ConnectionFile
        configuredRuntime = $resolved
        connectionState = $connectionState
        pairingMatches = $matches
        profileState = $profile
        managedCredentialRedirectPresent = [bool]$legacyRedirect
        launchOverridesPresent = $overrideNames.Count -gt 0
        launchOverrideNames = $overrideNames
        liveProcessVerified = $false
        guidance = 'Offline file check only. Shell environment is not proof of the running Burp environment. Load MCP first to initialize this PC runtime, then CPH. Recheck live REVIEW and get_cph_config success/managed/runtimeMatches. No reload during diagnosis.'
    }
}

function Assert-RuntimeMaintenance {
    # No automatic stopping and no process command lines (they may contain secrets).
    $processErrors = @()
    $processes = @(Get-Process -Name 'BurpSuite*' -ErrorAction SilentlyContinue -ErrorVariable processErrors)
    if (@($processErrors | Where-Object { $_.CategoryInfo.Category -ne 'ObjectNotFound' }).Count -gt 0) { throw 'PROCESS_CHECK_FAILED' }
    if ($processes.Count -gt 0) { throw 'BURP_MUST_BE_STOPPED' }
    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) { throw 'LISTENER_CHECK_UNAVAILABLE' }
    foreach ($port in @(9876,17866)) {
        $listenerErrors = @()
        $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue -ErrorVariable listenerErrors)
        if (@($listenerErrors | Where-Object { $_.CategoryInfo.Category -ne 'ObjectNotFound' }).Count -gt 0) { throw 'LISTENER_CHECK_FAILED' }
        if ($listeners.Count -gt 0) {
            throw 'BURP_LISTENER_STILL_ACTIVE'
        }
    }
    # Refuse configuration under an overriding launch environment. Never remove
    # or print its values, or pretend that an offline file fix changed a process.
    if (@(Get-ChildItem Env: | Where-Object { $_.Name -like 'BURP_DIAG_*' }).Count -gt 0) { throw 'LAUNCH_ENVIRONMENT_OVERRIDE_PRESENT' }
}

function Set-RuntimeConnection($Selection, [string]$BackupDirectory) {
    $before = Test-RuntimeConnection $Selection
    if ($before.profileState -in @('INVALID','PARTIAL','NOT_REVIEW')) { throw 'SELECTED_RUNTIME_PROFILE_NOT_READY' }
    # The managed MCP uses its own runtime directly; a legacy credential-only
    # redirect here cannot rebind its job store and must not be silently ignored.
    if (Test-Path -LiteralPath (Join-Path $Selection.McpRuntime 'cph-connection.json')) { throw 'MCP_LEGACY_REDIRECT_REQUIRES_REVIEW' }
    if ($before.pairingMatches) { return }
    $file = $Selection.ConnectionFile
    $data = if (Test-Path -LiteralPath $file -PathType Leaf) { Read-RuntimeJson $file } else { [pscustomobject]@{} }
    if ($data -isnot [pscustomobject]) { throw 'RUNTIME_REFERENCE_INVALID' }
    $reference = Get-RuntimeReference -FromDirectory (Split-Path -Parent $file) -ToDirectory $Selection.McpRuntime
    $data | Add-Member -NotePropertyName runtimeDirectory -NotePropertyValue $reference -Force
    $backupRoot = Get-RuntimeFullPath $BackupDirectory
    Assert-RuntimePlainPath $backupRoot
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    $unique = [Guid]::NewGuid().ToString('N')
    if (Test-Path -LiteralPath $file -PathType Leaf) {
        Copy-Item -LiteralPath $file -Destination (Join-Path $backupRoot "cph-connection.before.$unique.json")
    }
    $staged = Join-Path $backupRoot "cph-connection.staged.$unique.json"
    $json = $data | ConvertTo-Json -Depth 32
    [IO.File]::WriteAllText($staged, $json, (New-Object Text.UTF8Encoding($false)))
    New-Item -ItemType Directory -Path (Split-Path -Parent $file) -Force | Out-Null
    Copy-Item -LiteralPath $staged -Destination $file -Force
    $after = Test-RuntimeConnection $Selection
    if (-not $after.pairingMatches) { throw 'RUNTIME_REFERENCE_WRITE_FAILED' }
}
