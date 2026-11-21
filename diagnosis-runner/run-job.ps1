param(
    [Parameter(Mandatory=$true)][ValidateSet('prepare','run','start','poll','status','results','refresh_results','revoke','reconcile','renew_continuation')][string]$Action,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_-]{1,100}$')][string]$ExecutionId,
    [string]$JobFile,
    [string]$EvidenceRef
)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path $PSScriptRoot -Parent
$taskRuntime=Join-Path $taskRoot 'runtime'
$taskSettings=Get-Content -LiteralPath (Join-Path $taskRuntime 'settings.json') -Raw | ConvertFrom-Json
$taskSecrets=Get-Content -LiteralPath (Join-Path $taskRuntime 'operator-secrets.json') -Raw | ConvertFrom-Json
$taskRunner=Join-Path $PSScriptRoot 'build/install/diagnosis-runner/bin/diagnosis-runner.bat'
if(-not (Test-Path -LiteralPath $taskRunner)){throw 'runner配布物がありません。Gradle Wrapperで :diagnosis-runner:installDist を実行してください。'}
$taskStore=Join-Path $taskRuntime ('client-runs/'+$ExecutionId)
if($Action -eq 'prepare' -and -not $JobFile){throw 'prepareにはJobFileが必要です。'}
if($Action -eq 'reconcile' -and -not $EvidenceRef){throw 'reconcileにはEvidenceRefが必要です。'}
$taskPreviousUrl=$env:BURP_DIAG_WORKER_URL
$taskPreviousToken=$env:BURP_DIAG_WORKER_TOKEN
try {
    $env:BURP_DIAG_WORKER_URL=$taskSettings.workerUrl
    $env:BURP_DIAG_WORKER_TOKEN=$taskSecrets.worker
    $taskArguments=@($Action,$ExecutionId,$taskStore)
    if($Action -eq 'prepare'){$taskArguments+=(Resolve-Path -LiteralPath $JobFile).Path}
    if($Action -eq 'reconcile'){$taskArguments+=$EvidenceRef}
    & $taskRunner @taskArguments
    if($LASTEXITCODE -ne 0){throw ('runnerの操作に失敗しました: '+$Action)}
} finally {
    $env:BURP_DIAG_WORKER_URL=$taskPreviousUrl
    $env:BURP_DIAG_WORKER_TOKEN=$taskPreviousToken
}
