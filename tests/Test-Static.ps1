[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$failures = @()

foreach ($file in @(Get-ChildItem -Path $projectRoot -Recurse -Filter '*.ps1')) {
    $tokens = $null
    $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    foreach ($parseError in @($errors)) {
        $failures += "$($file.FullName):$($parseError.Extent.StartLineNumber): $($parseError.Message)"
    }
}

foreach ($file in @(Get-ChildItem -Path (Join-Path $projectRoot 'config') -Filter '*.json')) {
    try { $null = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json }
    catch { $failures += "$($file.FullName): invalid JSON: $($_.Exception.Message)" }
}

$entryText = Get-Content -LiteralPath (Join-Path $projectRoot 'envoy.ps1') -Raw
$exitPropagationCount = [regex]::Matches($entryText, 'if \(\$LASTEXITCODE -ne 0\) \{ exit \$LASTEXITCODE \}').Count
if ($exitPropagationCount -ne 3) { $failures += 'Top-level Smoke, Verify, and ComputeVerify actions do not all propagate child failure exit codes.' }
foreach ($exitControlledScript in @('Invoke-EnvoySmoke.ps1', 'Test-EnvoyNode.ps1', 'Test-EnvoyCompute.ps1')) {
    $exitControlledText = Get-Content -LiteralPath (Join-Path $projectRoot "scripts\$exitControlledScript") -Raw
    if ($exitControlledText -notmatch '(?m)^exit 0\r?$') { $failures += "$exitControlledScript does not reset its successful child-script exit status." }
}

$compose = Join-Path $projectRoot 'compute\compose.yaml'
$nativeProgramFiles = if ([string]::IsNullOrWhiteSpace($env:ProgramW6432)) { $env:ProgramFiles } else { $env:ProgramW6432 }
$staticDockerExe = Join-Path $nativeProgramFiles 'Docker\Docker\resources\bin\docker.exe'
if (Test-Path -LiteralPath $staticDockerExe -PathType Leaf) {
    $prior = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        if ((Get-AuthenticodeSignature -FilePath $staticDockerExe).Status -ne 'Valid') { $failures += 'Fixed Docker Desktop CLI signature is not valid.' }
        else {
            $composeOutput = (& $staticDockerExe compose --project-directory (Join-Path $projectRoot 'compute') -f $compose config 2>&1 | Out-String).Trim()
            if ($LASTEXITCODE -ne 0) { $failures += "Compose validation failed: $composeOutput" }
        }
    }
    finally { $ErrorActionPreference = $prior }
}

$composeText = Get-Content -LiteralPath $compose -Raw
if ($composeText -match '"0\.0\.0\.0:') { $failures += 'Compose publishes a service on all IPv4 interfaces.' }
if ($composeText -notmatch '127\.0\.0\.1:18080:8080') { $failures += 'Core probe is not bound to the expected loopback address.' }
if ($composeText -notmatch 'cap_drop:\s*\r?\n\s*- ALL') { $failures += 'Core probe does not drop all Linux capabilities.' }
if ($composeText -notmatch 'read_only:\s*true') { $failures += 'Core probe root filesystem is not read-only.' }

$pythonFile = Join-Path $projectRoot 'compute\app\server.py'
if (Get-Command python.exe -ErrorAction SilentlyContinue) {
    $pythonCode = "import ast,pathlib; ast.parse(pathlib.Path(r'$pythonFile').read_text(encoding='utf-8'))"
    $null = & python.exe -c $pythonCode
    if ($LASTEXITCODE -ne 0) { $failures += 'Python core probe failed syntax validation.' }
}

$verifyText = Get-Content -LiteralPath (Join-Path $projectRoot 'scripts\Test-EnvoyNode.ps1') -Raw
if ($verifyText -notmatch 'firewallInspectionComplete') { $failures += 'Verifier does not distinguish an incomplete firewall inspection from a clean result.' }
foreach ($requiredVerifierControl in @('strict-acceptance', 'Test-ExactInboundAuditRule', 'Test-ExactLiveOutboundBlockRule', 'Test-EffectiveSshConfiguration', 'Test-SafeUnmanagedSshConfig', 'Test-AuthorizedKeyAllowlist', 'Test-SshdServiceIdentity', 'Test-SshConfigurationAuthority', 'Test-RustDeskBinaryAuthority', 'Test-RustDeskServiceIdentity', 'Test-RustDeskDirectListenerIdentity', 'verifiedDesktopListenerIdentity.ServerProcess.ProcessId', 'ParentProcessId', 'serviceAccountSid', 'Queue[string]', 'SkipParentDirectory', 'sshd-service-identity', 'desiredTargetIsAdministrator', 'ssh-current-boot-proof', 'ssh-listener-ownership', 'tailscale-node-key-expiry', 'tailscale-forwarding-empty', 'desktop-security-config', 'desktop-firewall-conflicts', 'PolicyStoreSourceType', 'Platforms')) {
    if ($verifyText -notmatch [regex]::Escape($requiredVerifierControl)) { $failures += "Verifier is missing required control: $requiredVerifierControl" }
}

$accessText = Get-Content -LiteralPath (Join-Path $projectRoot 'scripts\Initialize-EnvoyAccess.ps1') -Raw
if ($accessText -notmatch 'Refusing to enable SSH') { $failures += 'SSH activation does not fail closed when firewall inspection is incomplete.' }
foreach ($requiredAccessControl in @('Assert-EffectiveSshConfiguration', 'Assert-NoUnsafeUnmanagedSshDirectives', 'AuthorizedKeysCommand', 'Assert-SshdListenerOwnership', 'Assert-SshdServiceIdentity', 'Protect-SshConfigurationDirectory', 'Protect-SshConfigurationFile', 'Assert-SshConfigurationAuthority', 'LocalSystem', 'Set-AuthorizedPublicKeys', 'machineFingerprint', 'ExpectedAdministrator', 'access.ssh.enabled', 'AcknowledgeTailnetControls', 'Assert-TailscaleHostKeyExpiry', 'daemonVersion', '0.0.1', 'serve', 'funnel', 'RebootProof', 'authenticationModeBeforeDisable', 'prepare-in-progress', 'proofReferenceTime')) {
    if ($accessText -notmatch [regex]::Escape($requiredAccessControl)) { $failures += "Access lifecycle is missing required control: $requiredAccessControl" }
}

$auditText = Get-Content -LiteralPath (Join-Path $projectRoot 'scripts\Get-EnvoyAudit.ps1') -Raw
foreach ($requiredAuditControl in @('Test-PortSpecificationIncludes', 'firewallProfilesSecure', 'AllowInboundRules', 'AllowLocalFirewallRules', 'preferencesVerified', 'unattendedMode', 'nodeKeyExpiryMode', 'versionMeetsSecurityFloor', 'daemonVersion', 'cliDaemonVersionsMatch', '0.0.1', 'npipe:////./pipe/docker_engine', 'serveInspectionComplete', 'funnelInspectionComplete', 'servicesInspectionComplete', 'driveInspectionComplete', 'driveSharesEmpty', 'outboundAllowBypassRules', 'outboundBlockRules', 'TracePolicyStore', 'Platforms', 'Get-NetFirewallApplicationFilter', 'Get-NetFirewallServiceFilter')) {
    if ($auditText -notmatch [regex]::Escape($requiredAuditControl)) { $failures += "Audit is missing required control: $requiredAuditControl" }
}
foreach ($requiredManagedDeviceControl in @('dsregcmd.exe', 'DomainJoined', 'AzureAdJoined', 'WorkplaceJoined', 'DiscoveryServiceFullURL', 'managedTargetPolicyPresent', 'managedDeviceOrPolicy', 'DEVICE_MANAGEMENT_INSPECTION_INCOMPLETE', 'MANAGED_DEVICE_OR_POLICY')) {
    if ($auditText -notmatch [regex]::Escape($requiredManagedDeviceControl)) { $failures += "Audit is missing managed-device stop control: $requiredManagedDeviceControl" }
}
foreach ($requiredTailscaleIdentityControl in @('cliSha256', 'cliSignerSubject', 'cliSignerThumbprint', 'serviceSha256', 'serviceSignerSubject', 'serviceSignerThumbprint', 'not signed by the same certificate')) {
    if ($auditText -notmatch [regex]::Escape($requiredTailscaleIdentityControl)) { $failures += "Audit is missing Tailscale executable identity binding: $requiredTailscaleIdentityControl" }
}

$desktopText = Get-Content -LiteralPath (Join-Path $projectRoot 'scripts\Initialize-EnvoyDesktop.ps1') -Raw
foreach ($requiredDesktopControl in @('Assert-RustDeskAccessFailedClosed', 'Assert-RustDeskBinaryAuthority', 'Assert-RustDeskServiceIdentity', 'Assert-RustDeskDirectListenerIdentity', 'Test-SafeEnvoyStateJournalTarget', 'rebootClosurePorts', 'Get-NetTCPConnection', 'Get-NetUDPEndpoint', 'ParentProcessId', 'serviceAccountSid', 'serverProcessIdAtEnable', 'Queue[string]', 'EnvoyNode-RustDesk-Block-Public-IPv4', 'EnvoyNode-RustDesk-Block-Public-IPv6', 'disableLanDiscovery', 'disableRemoteConfiguration', 'outboundAllowBypassRules', 'outboundBlockRules', 'serviceProcessIdAtEnable', 'machineFingerprint', 'enable-validation-in-progress', 'enabled-tailnet-only', 'desktopProofBootUtc', 'plannedRustDeskExe', 'requires the default protected Program Files\RustDesk\rustdesk.exe path')) {
    if ($desktopText -notmatch [regex]::Escape($requiredDesktopControl)) { $failures += "Desktop lifecycle is missing required control: $requiredDesktopControl" }
}
$desktopScopeGuard = [regex]::Match($desktopText, '(?m)^# Scope and identity checks precede every Enable mutation\.')
$desktopFirstStateMutationIndex = if ($desktopScopeGuard.Success) { $desktopText.IndexOf('Protect-EnvoyStateDirectory -Path $stateDir', $desktopScopeGuard.Index) } else { -1 }
if (-not $desktopScopeGuard.Success -or $desktopFirstStateMutationIndex -lt $desktopScopeGuard.Index) {
    $failures += 'Desktop Enable scope checks do not precede its first state mutation.'
}
else {
    $desktopPreMutationBlock = $desktopText.Substring($desktopScopeGuard.Index, $desktopFirstStateMutationIndex - $desktopScopeGuard.Index)
    foreach ($requiredPreMutationControl in @('if (-not $desktop.enabled)', 'AcknowledgeRustDeskConfigured', 'AcknowledgeRustDeskTailnetWhitelist', 'Assert-RustDeskServiceIdentity')) {
        if ($desktopPreMutationBlock -notmatch [regex]::Escape($requiredPreMutationControl)) { $failures += "Desktop Enable pre-mutation scope is missing: $requiredPreMutationControl" }
    }
}
$desktopRebootProofIndex = $desktopText.IndexOf("if (`$Stage -eq 'RebootProof') {")
$desktopRebootProofTryIndex = if ($desktopRebootProofIndex -ge 0) { $desktopText.IndexOf('try {', $desktopRebootProofIndex) } else { -1 }
$desktopRebootStateValidationIndex = if ($desktopRebootProofIndex -ge 0) { $desktopText.IndexOf('Test-ExactPrivilegedFileAcl -Path $desktopStatePath', $desktopRebootProofIndex) } else { -1 }
$desktopRebootCatchIndex = if ($desktopRebootProofTryIndex -ge 0) { $desktopText.IndexOf('catch {', $desktopRebootProofTryIndex) } else { -1 }
if ($desktopRebootProofIndex -lt 0 -or $desktopRebootProofTryIndex -lt 0 -or $desktopRebootStateValidationIndex -lt 0 -or $desktopRebootProofTryIndex -gt $desktopRebootStateValidationIndex -or $desktopRebootCatchIndex -lt $desktopRebootStateValidationIndex) {
    $failures += 'Desktop RebootProof security validation is not enclosed by its fail-close catch.'
}

$computeBootstrapText = Get-Content -LiteralPath (Join-Path $projectRoot 'scripts\Initialize-EnvoyCompute.ps1') -Raw
foreach ($requiredComputeControl in @(
    'machineFingerprint', 'windowsOwnerSid', 'dpkg --configure -a', 'marker-written-restart-required',
    'AcknowledgeWorkloadInterruption', 'Test-IsElevated', 'non-elevated PowerShell', 'Invoke-WslScriptChecked', 'bash -s --', 'RedirectStandardInput', 'BaseStream.Write', 'Assert-ExactComputeStateAcl',
    'ReparsePoint', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss', 'registration.version -ne 2',
    'Assert-ExactManagedMarker', 'journalCanAuthorizeAdoption = $false', 'local journals are never ownership proof',
    'passwd -S', "test ! -L '/home/__LINUX_USER__'", "sudo -n -l -U '__LINUX_USER__'", 'restart-required',
    'Get-ActiveComputeContainerIds', 'runningContainersBeforePackages', 'Package and Docker service maintenance may restart', '$bootstrapSmokeName', 'docker-compose-v2',
    'AcknowledgeCurrentBootAccessProof', 'AccessAcceptRebootProof has accepted a fresh second-device key-only proof'
)) {
    if ($computeBootstrapText -notmatch [regex]::Escape($requiredComputeControl)) { $failures += "Compute bootstrap is missing required control: $requiredComputeControl" }
}
if ($computeBootstrapText -match 'resumeOwnsUnmarkedDistro') { $failures += 'Compute bootstrap still permits journal-only adoption of an unmarked distribution.' }
$previewReturnIndex = $computeBootstrapText.IndexOf('if (-not $Apply)')
$approvedInventoryIndex = $computeBootstrapText.IndexOf('# Re-read inventory after approval/confirmation')
if ($previewReturnIndex -lt 0 -or $approvedInventoryIndex -lt 0 -or $previewReturnIndex -gt $approvedInventoryIndex) { $failures += 'Compute preview is not conclusively separated from approved live distro probing.' }
$markerWriteIndex = $computeBootstrapText.IndexOf("Write-EnvoyManagedMarker -Status 'bootstrap-in-progress'")
$userAddIndex = $computeBootstrapText.IndexOf('useradd --create-home')
if ($markerWriteIndex -lt 0 -or $userAddIndex -lt 0 -or $markerWriteIndex -gt $userAddIndex) { $failures += 'Compute ownership marker is not written before user/package mutations.' }

$computeVerifyText = Get-Content -LiteralPath (Join-Path $projectRoot 'scripts\Test-EnvoyCompute.ps1') -Raw
foreach ($requiredComputeVerifyControl in @('protectedStateValidated', 'exactMarkerValidated', 'hostNetworkContainers', 'unsafePublishedPorts', 'configuredTcpHosts', 'dockerdTcpListeners', 'daemon.json', 'MainPID', 'effectiveDefaultWslUser', 'directSudoersGrant', 'windowsDriveMounted', 'interopHandlerPresent', 'docker_output(["ps", "-aq"])', 'clean_docker_env', 'unix:///run/docker.sock', 'unixSocketSafe', '/run/docker.sock', 'docker.socket', 'SkipSmoke', 'smokeExecuted', 'OfflineOnly', 'offline-binding-only', 'RequireAlreadyRunning', 'Refusing to wake it from General Verify')) {
    if ($computeVerifyText -notmatch [regex]::Escape($requiredComputeVerifyControl)) { $failures += "Compute verification is missing required control: $requiredComputeVerifyControl" }
}

$exportText = Get-Content -LiteralPath (Join-Path $projectRoot 'scripts\Export-EnvoyCompute.ps1') -Raw
foreach ($requiredExportControl in @('docker-desktop', 'managedBy', 'machineFingerprint', 'Assert-ExactComputeStateAcl', 'registrationId', 'AcknowledgeActiveComputeContainers', 'docker --host unix:///run/docker.sock ps -q', "ScriptText 'sync'", 'filesystem-crash-consistent', 'explicit -Apply switch', 'Test-IsElevated', 'non-elevated PowerShell')) {
    if ($exportText -notmatch [regex]::Escape($requiredExportControl)) { $failures += "Compute export is missing required control: $requiredExportControl" }
}

$wrapperText = Get-Content -LiteralPath (Join-Path $projectRoot 'envoy.ps1') -Raw
if ($wrapperText -notmatch 'AcknowledgeActiveComputeContainers:\$AcknowledgeActiveComputeContainers') { $failures += 'Top-level CLI does not pass the active-container export acknowledgment end to end.' }
if ($wrapperText -notmatch 'AcknowledgeCurrentBootAccessProof:\$AcknowledgeCurrentBootAccessProof') { $failures += 'Top-level CLI does not pass the current-boot access-layer acknowledgment to compute bootstrap.' }
if ($wrapperText -notmatch "Export-EnvoyCompute\.ps1'.*-Apply") { $failures += 'Top-level CLI does not pass the mandatory export apply switch.' }

$nodeVerifyText = Get-Content -LiteralPath (Join-Path $projectRoot 'scripts\Test-EnvoyNode.ps1') -Raw
foreach ($requiredSafeVerifyControl in @('runningDistributionInspectionComplete', 'compute-offline-binding', '-OfflineOnly', 'General Verify left the on-demand distribution stopped', '-SkipSmoke', '-RequireAlreadyRunning')) {
    if ($nodeVerifyText -notmatch [regex]::Escape($requiredSafeVerifyControl)) { $failures += "General Verify is missing non-launching compute control: $requiredSafeVerifyControl" }
}

$auditSafeVerifyText = Get-Content -LiteralPath (Join-Path $projectRoot 'scripts\Get-EnvoyAudit.ps1') -Raw
foreach ($requiredRunningInventoryControl in @('Get-WslRunningInventory', 'inspectionComplete = $false', 'runningDistributionInspectionComplete')) {
    if ($auditSafeVerifyText -notmatch [regex]::Escape($requiredRunningInventoryControl)) { $failures += "Audit is missing conclusive running-distribution inventory control: $requiredRunningInventoryControl" }
}

$smokeText = Get-Content -LiteralPath (Join-Path $projectRoot 'scripts\Invoke-EnvoySmoke.ps1') -Raw
if ($smokeText -notmatch 'envoynode/core-probe:local' -or $smokeText -notmatch 'io\.envoynode\.base-digest' -or $smokeText -notmatch "--entrypoint', 'python") { $failures += 'Host smoke does not verify and explicitly execute the project-owned pinned-base image.' }
foreach ($requiredSmokeControl in @('Docker\Docker\resources\bin\docker.exe', 'Get-AuthenticodeSignature', 'npipe:////./pipe/docker_engine', '--pull=never', 'inspectedImageId')) {
    if ($smokeText -notmatch [regex]::Escape($requiredSmokeControl)) { $failures += "Host smoke is missing trusted local-engine control: $requiredSmokeControl" }
}

$buildSmokeText = Get-Content -LiteralPath (Join-Path $projectRoot 'scripts\Build-EnvoySmokeImage.ps1') -Raw
foreach ($requiredBuildControl in @('Docker\Docker\resources\bin\docker.exe', 'Get-AuthenticodeSignature', 'npipe:////./pipe/docker_engine', 'Refusing to replace the existing non-EnvoyNode image tag', 'core-probe:build-', 'io.envoynode.base-digest')) {
    if ($buildSmokeText -notmatch [regex]::Escape($requiredBuildControl)) { $failures += "Smoke image builder is missing collision-safety control: $requiredBuildControl" }
}

$planGuardText = Get-Content -LiteralPath (Join-Path $projectRoot 'scripts\Assert-EnvoyPlanApproval.ps1') -Raw
foreach ($requiredPlanControl in @('computedApprovalHash', 'expiresUtc', 'stateHash', 'configSha256', 'ApprovedPlanHash')) {
    if ($planGuardText -notmatch [regex]::Escape($requiredPlanControl)) { $failures += "Plan guard is missing required control: $requiredPlanControl" }
}
if ($planGuardText -match 'requirePlanReview\) \{ return \}' -or $planGuardText -notmatch [regex]::Escape('safety.requirePlanReview cannot be disabled or omitted')) {
    $failures += 'Plan guard still permits configuration to bypass mandatory reviewed-plan approval.'
}
foreach ($requiredBoundPlanField in @('tailscaleExecutableIdentity', 'desktopExecutable')) {
    if ($planGuardText -notmatch [regex]::Escape($requiredBoundPlanField)) { $failures += "Plan guard does not require executable identity field: $requiredBoundPlanField" }
}
if ($planGuardText -match "'Compute\*'.*code -match '\^\(UNSUPPORTED_COMPUTE") { $failures += 'Compute approval still filters out overlay/access blockers and can bypass lifecycle ordering.' }

$plannerText = Get-Content -LiteralPath (Join-Path $projectRoot 'scripts\New-EnvoyPlan.ps1') -Raw
foreach ($requiredPlannerControl in @('DEVICE_MANAGEMENT_INSPECTION_REQUIRED', 'MANAGED_DEVICE_OR_POLICY', 'HOST_SECURITY_DEFENDER_REQUIRED', 'HOST_SECURITY_UAC_REQUIRED', 'HOST_SECURITY_SECURE_BOOT_REQUIRED', 'HOST_SECURITY_ENCRYPTION_REQUIRED', 'tailscaleExecutableIdentity', 'desktopExecutableBinding', 'RUSTDESK_EXECUTABLE_IDENTITY_REQUIRED')) {
    if ($plannerText -notmatch [regex]::Escape($requiredPlannerControl)) { $failures += "Planner is missing release safety control: $requiredPlannerControl" }
}

$ignoreText = Get-Content -LiteralPath (Join-Path $projectRoot '.gitignore') -Raw
foreach ($requiredIgnore in @('/config/node.local.json', '/keys/', '/exports/', '/generated/', '/reports/*.json', '/state/', '*client-proof*.json', '*.key', '*.pem', '*.pfx', '*.p12', '*.ppk', '.env')) {
    if ($ignoreText -notmatch [regex]::Escape($requiredIgnore)) { $failures += "Git ignore policy is missing sensitive path or format: $requiredIgnore" }
}

if ((Get-Command git.exe -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $projectRoot '.git'))) {
    $trackedFiles = @(& git.exe -C $projectRoot ls-files)
    if ($LASTEXITCODE -ne 0) { $failures += 'Could not enumerate the tracked release set for sensitive-artifact validation.' }
    foreach ($trackedFile in $trackedFiles) {
        $normalized = $trackedFile.Replace('\', '/')
        if ($normalized -eq 'config/node.local.json' -or $normalized -like 'keys/*' -or $normalized -like 'exports/*' -or
            $normalized -like 'generated/*' -or $normalized -like 'reports/*.json' -or $normalized -like 'state/*' -or
            $normalized -like '*client-proof*.json') {
            $failures += "Sensitive or machine-generated artifact is tracked: $normalized"
            continue
        }
        $trackedPath = Join-Path $projectRoot $trackedFile
        if (-not (Test-Path -LiteralPath $trackedPath -PathType Leaf)) { continue }
        try { $trackedText = Get-Content -LiteralPath $trackedPath -Raw -ErrorAction Stop } catch { continue }
        foreach ($secretPattern in @('-----BEGIN (?:OPENSSH|RSA|EC|DSA|PRIVATE) PRIVATE KEY-----', '(?i)\b(?:gh[pousr]_|github_pat_|tskey-)[A-Za-z0-9_-]{16,}', '(?i)[A-Z]:\\Users\\[^\\\s"'']+', '(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/]{40,}={0,3}')) {
            if ($trackedText -match $secretPattern) { $failures += "Tracked file matches a forbidden secret/private-host pattern: $normalized"; break }
        }
    }
}

$clientProofText = Get-Content -LiteralPath (Join-Path $projectRoot 'scripts\New-EnvoyClientProof.ps1') -Raw
foreach ($requiredProofControl in @('Get-OpenSshClientTool', 'Challenge', 'signatureBase64', 'keyFingerprintToken', 'scanLines', 'lineTokens.Count -ne 1', 'uniqueScannedTokens.Count -ne 1', 'approvedScanLines')) {
    if ($clientProofText -notmatch [regex]::Escape($requiredProofControl)) { $failures += "Client proof generator is missing required control: $requiredProofControl" }
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) { Write-Output "FAIL: $failure" }
    throw "Static validation failed with $($failures.Count) issue(s)."
}

Write-Output 'PASS: PowerShell syntax, JSON, Compose, Python, loopback binding, and container restrictions validated.'
