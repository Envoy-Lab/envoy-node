[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Audit', 'Plan', 'Smoke', 'Verify', 'AccessPreview', 'AccessPrepare', 'AccessEnable', 'AccessHarden', 'AccessAcceptRebootProof', 'AccessDisable', 'DesktopPreview', 'DesktopEnable', 'DesktopAcceptRebootProof', 'DesktopDisable', 'ComputePreview', 'ComputeBootstrap', 'ComputeVerify', 'ExportCompute')]
    [string]$Action,

    [string]$Config,
    [string]$Output,
    [string]$Destination,
    [string]$PublicKeyPath,
    [string]$TargetUser,
    [string]$ClientProofPath,
    [string]$ApprovedPlanHash,
    [string]$ApprovedPlanPath,
    [string]$RustDeskExe,
    [switch]$Apply,
    [switch]$Json,
    [switch]$AcknowledgeAdministratorTarget,
    [switch]$AcknowledgeTailnetControls,
    [switch]$AcknowledgeRustDeskConfigured,
    [switch]$AcknowledgeRustDeskTailnetWhitelist,
    [switch]$AcknowledgeRustDeskPostRebootClientTest,
    [switch]$AcknowledgeCurrentBootAccessProof,
    [switch]$AcknowledgeWorkloadInterruption,
    [switch]$AcknowledgeActiveComputeContainers
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($Config)) {
    $Config = Join-Path $scriptRoot 'config\node.example.json'
}
$scripts = Join-Path $scriptRoot 'scripts'

switch ($Action) {
    'Audit' {
        & (Join-Path $scripts 'Get-EnvoyAudit.ps1') -OutputPath $Output -Json:$Json
    }
    'Plan' {
        & (Join-Path $scripts 'New-EnvoyPlan.ps1') -ConfigPath $Config -OutputPath $Output -Json:$Json
    }
    'Smoke' {
        & (Join-Path $scripts 'Invoke-EnvoySmoke.ps1') -OutputPath $Output -Json:$Json
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    'Verify' {
        & (Join-Path $scripts 'Test-EnvoyNode.ps1') -ConfigPath $Config -OutputPath $Output -Json:$Json
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    'AccessPreview' {
        & (Join-Path $scripts 'Initialize-EnvoyAccess.ps1') -Stage Preview -ConfigPath $Config -PublicKeyPath $PublicKeyPath -TargetUser $TargetUser
    }
    'AccessPrepare' {
        if (-not $Apply) { throw 'AccessPrepare is mutating. Re-run with -Apply only after reviewing AccessPreview.' }
        & (Join-Path $scripts 'Initialize-EnvoyAccess.ps1') -Stage Prepare -ConfigPath $Config -PublicKeyPath $PublicKeyPath -TargetUser $TargetUser -ApprovedPlanHash $ApprovedPlanHash -ApprovedPlanPath $ApprovedPlanPath -Apply -AcknowledgeAdministratorTarget:$AcknowledgeAdministratorTarget
    }
    'AccessEnable' {
        if (-not $Apply) { throw 'AccessEnable is mutating. Re-run with -Apply only after Tailscale enrollment and policy review.' }
        & (Join-Path $scripts 'Initialize-EnvoyAccess.ps1') -Stage Enable -ConfigPath $Config -TargetUser $TargetUser -ApprovedPlanHash $ApprovedPlanHash -ApprovedPlanPath $ApprovedPlanPath -Apply -AcknowledgeAdministratorTarget:$AcknowledgeAdministratorTarget -AcknowledgeTailnetControls:$AcknowledgeTailnetControls
    }
    'AccessHarden' {
        if (-not $Apply) { throw 'AccessHarden is mutating and requires a fresh second-device proof.' }
        & (Join-Path $scripts 'Initialize-EnvoyAccess.ps1') -Stage Harden -ConfigPath $Config -TargetUser $TargetUser -ClientProofPath $ClientProofPath -ApprovedPlanHash $ApprovedPlanHash -ApprovedPlanPath $ApprovedPlanPath -Apply -AcknowledgeAdministratorTarget:$AcknowledgeAdministratorTarget
    }
    'AccessAcceptRebootProof' {
        if (-not $Apply) { throw 'AccessAcceptRebootProof records a fresh post-reboot second-device proof and requires -Apply.' }
        & (Join-Path $scripts 'Initialize-EnvoyAccess.ps1') -Stage RebootProof -ConfigPath $Config -TargetUser $TargetUser -ClientProofPath $ClientProofPath -ApprovedPlanHash $ApprovedPlanHash -ApprovedPlanPath $ApprovedPlanPath -Apply -AcknowledgeAdministratorTarget:$AcknowledgeAdministratorTarget
    }
    'AccessDisable' {
        if (-not $Apply) { throw 'AccessDisable stops managed remote listeners. Re-run with -Apply from the local console.' }
        & (Join-Path $scripts 'Initialize-EnvoyAccess.ps1') -Stage Disable -ConfigPath $Config -Apply
    }
    'DesktopPreview' {
        & (Join-Path $scripts 'Initialize-EnvoyDesktop.ps1') -Stage Preview -ConfigPath $Config -RustDeskExe $RustDeskExe
    }
    'DesktopEnable' {
        if (-not $Apply) { throw 'DesktopEnable is mutating. Configure RustDesk interactively and re-run with -Apply.' }
        & (Join-Path $scripts 'Initialize-EnvoyDesktop.ps1') -Stage Enable -ConfigPath $Config -RustDeskExe $RustDeskExe -ApprovedPlanHash $ApprovedPlanHash -ApprovedPlanPath $ApprovedPlanPath -AcknowledgeRustDeskConfigured:$AcknowledgeRustDeskConfigured -AcknowledgeRustDeskTailnetWhitelist:$AcknowledgeRustDeskTailnetWhitelist -Apply
    }
    'DesktopAcceptRebootProof' {
        if (-not $Apply) { throw 'DesktopAcceptRebootProof records reboot-safe GUI recovery and requires -Apply.' }
        & (Join-Path $scripts 'Initialize-EnvoyDesktop.ps1') -Stage RebootProof -ConfigPath $Config -RustDeskExe $RustDeskExe -ApprovedPlanHash $ApprovedPlanHash -ApprovedPlanPath $ApprovedPlanPath -AcknowledgeRustDeskTailnetWhitelist:$AcknowledgeRustDeskTailnetWhitelist -AcknowledgeRustDeskPostRebootClientTest:$AcknowledgeRustDeskPostRebootClientTest -Apply
    }
    'DesktopDisable' {
        if (-not $Apply) { throw 'DesktopDisable closes the managed GUI path. Re-run with -Apply from the local console or SSH.' }
        & (Join-Path $scripts 'Initialize-EnvoyDesktop.ps1') -Stage Disable -ConfigPath $Config -RustDeskExe $RustDeskExe -Apply
    }
    'ComputePreview' {
        & (Join-Path $scripts 'Initialize-EnvoyCompute.ps1') -ConfigPath $Config
    }
    'ComputeBootstrap' {
        if (-not $Apply) {
            throw 'ComputeBootstrap is mutating. Re-run with -Apply only after reviewing ComputePreview.'
        }
        & (Join-Path $scripts 'Initialize-EnvoyCompute.ps1') -ConfigPath $Config -ApprovedPlanHash $ApprovedPlanHash -ApprovedPlanPath $ApprovedPlanPath -Apply -AcknowledgeCurrentBootAccessProof:$AcknowledgeCurrentBootAccessProof -AcknowledgeWorkloadInterruption:$AcknowledgeWorkloadInterruption
    }
    'ComputeVerify' {
        & (Join-Path $scripts 'Test-EnvoyCompute.ps1') -ConfigPath $Config -OutputPath $Output -Json:$Json
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    'ExportCompute' {
        if (-not $Apply) {
            throw 'ExportCompute writes a potentially large snapshot. Review and optionally set -Destination, then re-run with -Apply.'
        }
        & (Join-Path $scripts 'Export-EnvoyCompute.ps1') -ConfigPath $Config -Destination $Destination -ApprovedPlanHash $ApprovedPlanHash -ApprovedPlanPath $ApprovedPlanPath -Apply -AcknowledgeWorkloadInterruption:$AcknowledgeWorkloadInterruption -AcknowledgeActiveComputeContainers:$AcknowledgeActiveComputeContainers
    }
}
