[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Action,
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [string]$ApprovedPlanHash,
    [string]$ApprovedPlanPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
if (-not ($config.PSObject.Properties.Name -contains 'safety') -or
    -not ($config.safety.PSObject.Properties.Name -contains 'requirePlanReview') -or
    [bool]$config.safety.requirePlanReview -ne $true) {
    throw 'safety.requirePlanReview cannot be disabled or omitted. Every non-emergency mutation requires a fresh reviewed plan.'
}
if ([string]::IsNullOrWhiteSpace($ApprovedPlanHash) -or $ApprovedPlanHash -notmatch '^[a-fA-F0-9]{64}$') {
    throw 'Every non-emergency mutation requires a reviewed plan. Generate Plan, review it, then pass its 64-character hash with -ApprovedPlanHash.'
}
$projectRoot = Split-Path $PSScriptRoot -Parent
if ([string]::IsNullOrWhiteSpace($ApprovedPlanPath)) { $ApprovedPlanPath = Join-Path $projectRoot 'reports\plan-latest.json' }
if (-not (Test-Path -LiteralPath $ApprovedPlanPath -PathType Leaf)) { throw "The approved plan artifact is missing: $ApprovedPlanPath" }
$approved = Get-Content -LiteralPath $ApprovedPlanPath -Raw | ConvertFrom-Json
$required = @('planHash', 'stateHash', 'configSha256', 'plan')
if (@($required | Where-Object { $_ -notin @($approved.PSObject.Properties.Name) }).Count -gt 0) { throw 'The approved plan artifact is malformed.' }
$requiredPlanFields = @('planVersion', 'generatedUtc', 'expiresUtc', 'machineFingerprint', 'plannerUserSid', 'plannerElevated', 'sshTarget', 'tailscaleExecutableIdentity', 'desktopExecutable', 'publicKeyManifest')
if (@($requiredPlanFields | Where-Object { $_ -notin @($approved.plan.PSObject.Properties.Name) }).Count -gt 0) { throw 'The approved plan artifact predates required identity/key-manifest binding or is malformed.' }
if ([string]$approved.planHash -cne $ApprovedPlanHash.ToLowerInvariant()) { throw 'The supplied approval hash does not match the reviewed plan artifact.' }
$approvalBody = [pscustomobject][ordered]@{ stateHash = [string]$approved.stateHash; configSha256 = [string]$approved.configSha256; plan = $approved.plan }
$approvalCanonical = $approvalBody | ConvertTo-Json -Depth 12 -Compress
$sha = [Security.Cryptography.SHA256]::Create()
try { $computedApprovalHash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($approvalCanonical))) -replace '-', '').ToLowerInvariant() }
finally { $sha.Dispose() }
if ($computedApprovalHash -cne [string]$approved.planHash) { throw 'The reviewed plan artifact was modified after its approval hash was generated.' }
$liveConfigHash = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ([string]$approved.configSha256 -cne $liveConfigHash) { throw 'The configuration changed after plan review. Generate and review a fresh plan.' }
try { $expiresUtc = [DateTime]::Parse([string]$approved.plan.expiresUtc).ToUniversalTime() }
catch { throw 'The approved plan expiry is invalid.' }
if ($expiresUtc -le [DateTime]::UtcNow) { throw 'The reviewed plan expired. Generate and review a fresh plan.' }

$current = & (Join-Path $PSScriptRoot 'New-EnvoyPlan.ps1') -ConfigPath $ConfigPath -PassThru -NoReport
if ([string]$current.plan.machineFingerprint -cne [string]$approved.plan.machineFingerprint) { throw 'The approved plan belongs to a different Windows installation.' }
if ([string]$current.plan.plannerUserSid -cne [string]$approved.plan.plannerUserSid -or [bool]$current.plan.plannerElevated -ne [bool]$approved.plan.plannerElevated) { throw 'The approved plan was generated under a different Windows identity or elevation context.' }
$currentSshTarget = $current.plan.sshTarget | ConvertTo-Json -Depth 5 -Compress
$approvedSshTarget = $approved.plan.sshTarget | ConvertTo-Json -Depth 5 -Compress
if ($currentSshTarget -cne $approvedSshTarget) { throw 'The configured SSH target account name, SID, existence, or administrator status changed after plan review.' }
$currentKeyManifest = $current.plan.publicKeyManifest | ConvertTo-Json -Depth 6 -Compress
$approvedKeyManifest = $approved.plan.publicKeyManifest | ConvertTo-Json -Depth 6 -Compress
if ($currentKeyManifest -cne $approvedKeyManifest) { throw 'A reviewed SSH public-key file, fingerprint, path, or content hash changed after plan approval.' }
if ([string]$current.stateHash -cne [string]$approved.stateHash) { throw 'Machine state or safety findings changed after plan review. Generate and review a fresh plan.' }

$blockers = @($current.plan.blockers)
switch -Wildcard ($Action) {
    'Compute*' { $relevant = @($blockers | Where-Object { $_.code -notmatch '^(RDP_|UNSUPPORTED_DESKTOP|RUSTDESK_|HOST_SECURITY_)' }) }
    'ExportCompute' { $relevant = @($blockers | Where-Object { $_.code -notmatch '^(RDP_|UNSUPPORTED_DESKTOP|RUSTDESK_|HOST_SECURITY_)' }) }
    'Desktop*' { $relevant = @($blockers | Where-Object { $_.code -notmatch '^(UNSUPPORTED_COMPUTE|WSL_|GLOBAL_WSL|COMPUTE_|GPU_)' }) }
    default { $relevant = @($blockers | Where-Object { $_.code -notmatch '^(RDP_|UNSUPPORTED_DESKTOP|RUSTDESK_|UNSUPPORTED_COMPUTE|WSL_|GLOBAL_WSL|COMPUTE_|GPU_)' }) }
}
if ($relevant.Count -gt 0) { throw "The reviewed plan still has $($relevant.Count) blocker(s) relevant to $Action. Resolve them and review a fresh zero-blocker plan." }
