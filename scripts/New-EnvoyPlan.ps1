[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [string]$OutputPath,
    [switch]$Json,
    [switch]$PassThru,
    [switch]$NoReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Configuration file not found: $ConfigPath"
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$resolvedConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
$configDirectory = Split-Path $resolvedConfigPath -Parent
if ($config.schemaVersion -ne 1) { throw 'Only schemaVersion 1 is supported.' }
if ($config.access.exposePublicPorts -ne $false) { throw 'Refusing a configuration that exposes public ports.' }
if ($config.compute.resources.memoryGB -lt 4) { throw 'compute.resources.memoryGB must be at least 4.' }
if ($config.compute.resources.processors -lt 1) { throw 'compute.resources.processors must be at least 1.' }
if ($config.compute.resources.swapGB -lt 0) { throw 'compute.resources.swapGB cannot be negative.' }
if ($config.access.ssh.port -lt 1 -or $config.access.ssh.port -gt 65535) { throw 'SSH port is invalid.' }
if ($config.access.desktop.port -lt 1 -or $config.access.desktop.port -gt 65535) { throw 'Desktop port is invalid.' }

$auditScript = Join-Path $PSScriptRoot 'Get-EnvoyAudit.ps1'
$auditPorts = @([int]$config.access.ssh.port, [int]$config.access.desktop.port)
$audit = & $auditScript -AdditionalSensitivePorts $auditPorts -PassThru -NoReport

$steps = New-Object System.Collections.Generic.List[object]
$blockers = New-Object System.Collections.Generic.List[object]
$warnings = New-Object System.Collections.Generic.List[object]

function Add-Step {
    param(
        [string]$Id,
        [string]$Layer,
        [string]$Action,
        [bool]$Mutating,
        [string]$Gate,
        [string]$Rollback
    )
    $steps.Add([pscustomobject][ordered]@{
        id = $Id
        layer = $Layer
        action = $Action
        mutating = $Mutating
        approvalGate = $Gate
        rollback = $Rollback
    })
}

function Add-Blocker { param([string]$Code, [string]$Message) $blockers.Add([pscustomobject][ordered]@{ code = $Code; message = $Message }) }
function Add-Warning { param([string]$Code, [string]$Message) $warnings.Add([pscustomobject][ordered]@{ code = $Code; message = $Message }) }

Add-Step 'audit' 'host' 'Capture redacted host, security, access, and compute facts.' $false 'none' 'none'

if (-not ($config.PSObject.Properties.Name -contains 'safety') -or
    -not ($config.safety.PSObject.Properties.Name -contains 'requirePlanReview') -or
    [bool]$config.safety.requirePlanReview -ne $true) {
    Add-Blocker 'PLAN_REVIEW_POLICY_REQUIRED' 'safety.requirePlanReview cannot be disabled or omitted.'
}
if (-not ($config.PSObject.Properties.Name -contains 'safety') -or
    -not ($config.safety.PSObject.Properties.Name -contains 'requireSecondDeviceProof') -or
    [bool]$config.safety.requireSecondDeviceProof -ne $true) {
    Add-Blocker 'SECOND_DEVICE_PROOF_POLICY_REQUIRED' 'safety.requireSecondDeviceProof cannot be disabled or omitted.'
}
if (-not $audit.management.inspectionComplete) {
    Add-Blocker 'DEVICE_MANAGEMENT_INSPECTION_REQUIRED' 'Domain, Entra ID/workplace join, MDM enrollment, and managed firewall/OpenSSH/RustDesk policy must be inspected conclusively before mutation.'
}
elseif ($audit.management.managedDeviceOrPolicy) {
    Add-Blocker 'MANAGED_DEVICE_OR_POLICY' 'Enterprise/domain/Entra/workplace join, MDM enrollment, or managed target policy was detected. Stop and use the responsible administrator or policy authority.'
}
if (-not $audit.security.defender -or -not $audit.security.defender.RealTimeProtectionEnabled) {
    Add-Blocker 'HOST_SECURITY_DEFENDER_REQUIRED' 'Microsoft Defender real-time protection must be conclusively enabled before access or desktop mutation.'
}
if (-not $audit.security.uacInspectionComplete -or -not $audit.security.uacEnabled) {
    Add-Blocker 'HOST_SECURITY_UAC_REQUIRED' 'User Account Control must be conclusively enabled before access or desktop mutation.'
}
if (-not $audit.security.secureBootInspectionComplete -or -not $audit.security.secureBootEnabled) {
    Add-Blocker 'HOST_SECURITY_SECURE_BOOT_REQUIRED' 'Secure Boot must be conclusively enabled before access or desktop mutation.'
}
if ($audit.security.systemDriveEncryption.Protection -notmatch 'On') {
    Add-Blocker 'HOST_SECURITY_ENCRYPTION_REQUIRED' 'System-drive encryption protection must be conclusively on before access or desktop mutation.'
}

$configuredSshTarget = if ([string]::IsNullOrWhiteSpace([string]$config.access.ssh.targetUser)) { $env:USERNAME } else { [string]$config.access.ssh.targetUser }
$sshTargetBinding = [pscustomobject][ordered]@{
    configuredValue = [string]$config.access.ssh.targetUser
    resolvedName = $configuredSshTarget
    sid = $null
    isAdministrator = $null
    exists = $false
}
try {
    $targetAccount = Get-LocalUser -Name $configuredSshTarget -ErrorAction Stop
    $adminMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
    $sshTargetBinding.resolvedName = [string]$targetAccount.Name
    $sshTargetBinding.sid = [string]$targetAccount.SID.Value
    $sshTargetBinding.isAdministrator = [bool]($adminMembers | Where-Object { $_.SID.Value -eq $targetAccount.SID.Value })
    $sshTargetBinding.exists = $true
}
catch {
    Add-Blocker 'SSH_TARGET_ACCOUNT_UNRESOLVED' "The configured SSH target '$configuredSshTarget' could not be resolved to one local account and administrator status."
}

if ($config.access.overlay.provider -ne 'tailscale') {
    Add-Blocker 'UNSUPPORTED_OVERLAY' 'This release supports Tailscale only. Headscale is a future adapter.'
}
elseif (-not $audit.access.tailscale.installed) {
    Add-Blocker 'TAILSCALE_MANUAL_INSTALL_REQUIRED' 'Install the official signed Tailscale Windows client interactively, then generate a fresh plan. EnvoyNode never performs an elevated package-manager install.'
}
elseif (-not $audit.access.tailscale.installationTrusted) {
    Add-Blocker 'TAILSCALE_INSTALLATION_UNTRUSTED' 'The fixed-path Tailscale CLI, registered service path, and Authenticode signatures could not be correlated and trusted.'
}
elseif (-not $audit.access.tailscale.versionMeetsSecurityFloor) {
    Add-Blocker 'TAILSCALE_VERSION_TOO_OLD' 'Upgrade the official Tailscale client to 1.98.9 or newer before enrollment or access activation.'
}
elseif (-not $audit.access.tailscale.serveInspectionComplete -or -not $audit.access.tailscale.funnelInspectionComplete -or -not $audit.access.tailscale.servicesInspectionComplete -or -not $audit.access.tailscale.driveInspectionComplete) {
    Add-Blocker 'TAILSCALE_EXTRA_SURFACES_UNVERIFIED' 'Tailscale Serve, Funnel, Services, and Taildrive share state must all be read successfully before remote-access mutation.'
}
elseif (-not $audit.access.tailscale.serveConfigEmpty -or -not $audit.access.tailscale.funnelConfigEmpty -or -not $audit.access.tailscale.servicesConfigEmpty -or -not $audit.access.tailscale.driveSharesEmpty) {
    Add-Blocker 'TAILSCALE_EXTRA_SURFACES_CONFIGURED' 'Remove every persistent Tailscale Serve/Funnel/Services forward and Taildrive share, then generate a fresh plan.'
}
elseif (-not $audit.access.tailscale.online -or $audit.access.tailscale.serviceStatus -ne 'Running' -or $audit.access.tailscale.serviceStartType -ne 'Automatic' -or
    -not $audit.access.tailscale.preferencesVerified -or -not $audit.access.tailscale.unattendedMode -or -not $audit.access.tailscale.unsafeServerFeaturesOff -or -not $audit.access.tailscale.incomingConnectionsEnabled) {
    Add-Blocker 'TAILSCALE_RUNTIME_NOT_READY' 'Tailscale must be online, Running/Automatic, unattended, accepting tailnet connections, and free of SSH/web/remote-config/exit/subnet features.'
}

if (-not $config.access.overlay.unattended -or -not $config.access.overlay.requireMfa -or -not $config.access.overlay.requireDeviceApproval) {
    Add-Blocker 'TAILNET_CONTROLS_REQUIRED' 'Unattended host mode, MFA, and device approval must all remain required.'
}

switch ([string]$config.access.overlay.hostKeyExpiry) {
    'keep-enabled' {
        if ($audit.access.tailscale.installationTrusted) {
            $expiryReady = $false
            if ($audit.access.tailscale.nodeKeyExpiryMode -eq 'enabled' -and -not $audit.access.tailscale.nodeKeyExpired -and -not [string]::IsNullOrWhiteSpace([string]$audit.access.tailscale.nodeKeyExpiryUtc)) {
                try { $expiryReady = [DateTime]::Parse([string]$audit.access.tailscale.nodeKeyExpiryUtc).ToUniversalTime() -ge [DateTime]::UtcNow.AddDays(30) } catch { }
            }
            if (-not $expiryReady) { Add-Blocker 'TAILSCALE_HOST_EXPIRY_NOT_READY' 'Node-key expiry must be enabled, unexpired, and at least 30 days away for this pilot policy.' }
        }
        Add-Warning 'TAILSCALE_HOST_REAUTH_REQUIRED' 'Host node-key expiry remains enabled. Reauthenticate before the remaining lifetime enters the 30-day acceptance window.'
    }
    'disable-for-unattended-host' {
        if ($audit.access.tailscale.installationTrusted -and $audit.access.tailscale.nodeKeyExpiryMode -ne 'disabled') { Add-Blocker 'TAILSCALE_HOST_EXPIRY_NOT_DISABLED' 'This availability policy requires node-key expiry to be disabled explicitly for this reviewed host.' }
        Add-Warning 'TAILSCALE_HOST_EXPIRY_DISABLED' 'The host is configured for uninterrupted availability by disabling node-key expiry. Revoke it promptly if lost or retired.'
    }
    default { Add-Blocker 'TAILSCALE_HOST_EXPIRY_POLICY_INVALID' "Set access.overlay.hostKeyExpiry to 'keep-enabled' or 'disable-for-unattended-host'." }
}

Add-Step 'enroll-overlay' 'overlay' 'Authenticate interactively with MFA, approve both devices, replace allow-all policy, enable unattended mode, omit Taildrive grants, and disable Taildrop/Send Files.' $true 'human identity and policy review' 'Revoke the node in the Tailscale admin console.'

$publicKeyManifest = New-Object System.Collections.Generic.List[object]
if ($config.access.ssh.enabled) {
    $configuredPublicKeys = @($config.access.ssh.publicKeyFiles)
    if ($configuredPublicKeys.Count -eq 0) {
        Add-Blocker 'SSH_PUBLIC_KEY_REQUIRED' 'Add at least one client .pub path. Never place a private key here.'
    }
    foreach ($configuredPublicKey in $configuredPublicKeys) {
        $candidate = [string]$configuredPublicKey
        if (-not [IO.Path]::IsPathRooted($candidate)) { $candidate = Join-Path $configDirectory $candidate }
        if (-not (Test-Path -LiteralPath $candidate)) {
            $publicKeyManifest.Add([pscustomobject][ordered]@{ configuredPath = [string]$configuredPublicKey; resolvedPath = [IO.Path]::GetFullPath($candidate); exists = $false; fileSha256 = $null; keyType = $null; fingerprint = $null })
            Add-Blocker 'SSH_PUBLIC_KEY_MISSING' "A reviewed public-key file does not exist: $configuredPublicKey"
            continue
        }
        $resolvedKeyPath = (Resolve-Path -LiteralPath $candidate).Path
        $keyText = (Get-Content -LiteralPath $candidate -Raw).Trim()
        $keyType = $null
        $keyFingerprint = $null
        if ($keyText -match 'PRIVATE KEY' -or $keyText -notmatch '^(ssh-ed25519|sk-ssh-ed25519@openssh\.com)\s+[A-Za-z0-9+/=]+(?:\s+.*)?$') {
            Add-Blocker 'SSH_PUBLIC_KEY_INVALID' "A configured key is not one Ed25519 public-key line: $configuredPublicKey"
        }
        else {
            $keyType = ($keyText -split '\s+')[0]
            try {
                $keyBlob = [Convert]::FromBase64String(($keyText -split '\s+')[1])
                $keySha = [Security.Cryptography.SHA256]::Create()
                try { $keyFingerprint = 'SHA256:' + [Convert]::ToBase64String($keySha.ComputeHash($keyBlob)).TrimEnd('=') }
                finally { $keySha.Dispose() }
            }
            catch { Add-Blocker 'SSH_PUBLIC_KEY_INVALID' "A configured public key has invalid encoded material: $configuredPublicKey" }
        }
        $publicKeyManifest.Add([pscustomobject][ordered]@{
            configuredPath = [string]$configuredPublicKey
            resolvedPath = $resolvedKeyPath
            exists = $true
            fileSha256 = (Get-FileHash -LiteralPath $resolvedKeyPath -Algorithm SHA256).Hash.ToLowerInvariant()
            keyType = $keyType
            fingerprint = $keyFingerprint
        })
    }
    $duplicateKeyFingerprints = @($publicKeyManifest | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.fingerprint) } | Group-Object fingerprint | Where-Object Count -gt 1)
    if ($duplicateKeyFingerprints.Count -gt 0) { Add-Blocker 'SSH_PUBLIC_KEY_DUPLICATE' 'The reviewed public-key manifest contains duplicate key fingerprints.' }
    if ($config.access.ssh.createStandardUser) { Add-Blocker 'ACCOUNT_CREATION_NOT_AUTOMATED' 'This release never creates or passwords a Windows account. Create and initialize a standard account locally, then set targetUser explicitly.' }
    if ($config.access.ssh.passwordMode -ne 'bootstrap-until-proven') { Add-Blocker 'SSH_PROOF_MODE_REQUIRED' 'SSH must use bootstrap-until-proven so password removal follows a fresh second-device key proof.' }
    if (-not $audit.access.openssh.serverServicePresent) {
        Add-Step 'install-openssh' 'access' 'Install the Microsoft-supported Windows OpenSSH Server capability; immediately disable its broad installer firewall rule.' $true 'elevated approved apply' 'Restore prior capability state only if this framework installed it.'
    }
    Add-Step 'authorize-client' 'access' 'Refuse unexpected existing keys, back up the file, and atomically install exactly the configured public-key allowlist with protected ACLs.' $true 'public-key fingerprint and allowlist review' 'Restore the recorded authorized-keys backup locally.'
    Add-Step 'scope-ssh-firewall' 'access' 'Create exact program, address, client-range, port, and adapter filters; keep the broad installer rule disabled.' $true 'adapter uniqueness and tailnet policy proof' 'Remove EnvoyNode-owned rules and preserve the broad installer rule disabled.'
    Add-Step 'validate-and-start-sshd' 'access' 'Validate sshd_config, start sshd, and record the host-key fingerprint.' $true 'local console remains available' 'Restore config bytes/ACLs, then leave sshd stopped and startup-disabled until a new approved attempt.'
    Add-Step 'prove-client' 'access' 'From the second laptop, verify the pinned host key and execute a random nonce using public-key authentication.' $false 'separate-device proof' 'none'
    Add-Step 'finalize-key-only' 'access' 'Disable SSH password authentication only after the proof is accepted.' $true 'matching client proof' 'Restore the pre-finalize configuration.'
    Add-Step 'prove-current-boot' 'access' 'After a deliberate reboot, accept a fresh key-only proof from the second laptop and bind acceptance to that Windows boot.' $true 'local recovery plus second-device post-reboot proof' 'Repeat the proof after a later reboot or access-layer change.'
}

if ($config.access.desktop.enabled) {
    if ($config.access.desktop.provider -eq 'rdp' -and -not $audit.access.desktop.rdpHostSupported) {
        Add-Blocker 'RDP_UNSUPPORTED_EDITION' 'Windows Home cannot host Microsoft RDP. Use rustdesk-direct or leave desktop disabled.'
    }
    elseif ($config.access.desktop.provider -eq 'rustdesk-direct') {
        if ($config.access.desktop.requireTailnetWhitelist -ne $true -or $config.access.desktop.blockPublicRustDeskEgress -ne $true -or $config.access.desktop.disableLanDiscovery -ne $true -or $config.access.desktop.disableRemoteConfiguration -ne $true) {
            Add-Blocker 'RUSTDESK_PRIVATE_PATH_REQUIRED' 'RustDesk requires a tailnet IP whitelist, EnvoyNode public-egress blocks, disabled LAN discovery, and disabled remote configuration.'
        }
        Add-Step 'configure-rustdesk' 'desktop' 'Download the official signed RustDesk installer, disconnect all networking, install/configure direct IP, whitelist only approved tailnet ranges, set a unique permanent password, then exit and stop/startup-disable the service before reconnecting.' $true 'offline quarantine, separate desktop-service approval, and interactive password entry' 'Keep the RustDesk service startup-disabled and remove or preserve only reviewed EnvoyNode rules.'
        Add-Step 'scope-desktop-firewall' 'desktop' 'Permit the RustDesk direct port only through the detected Tailscale adapter.' $true 'fresh SSH recovery path proven' 'Fail closed by disabling managed ingress, stopping/startup-disabling RustDesk, and preserving or enabling managed public-egress blocks.'
    }
    else {
        Add-Blocker 'UNSUPPORTED_DESKTOP' 'Desktop provider must be rustdesk-direct on Windows Home.'
    }
}

$nativeProgramFiles = if ([string]::IsNullOrWhiteSpace($env:ProgramW6432)) { $env:ProgramFiles } else { $env:ProgramW6432 }
$plannedRustDeskPath = [IO.Path]::GetFullPath((Join-Path $nativeProgramFiles 'RustDesk\rustdesk.exe'))
$desktopExecutableBinding = [pscustomobject][ordered]@{
    path = $plannedRustDeskPath
    exists = $false
    sha256 = $null
    signatureStatus = $null
    signerSubject = $null
    signerThumbprint = $null
    productVersion = $null
}
if (Test-Path -LiteralPath $plannedRustDeskPath -PathType Leaf) {
    $desktopExecutableBinding.exists = $true
    $desktopExecutableBinding.sha256 = (Get-FileHash -LiteralPath $plannedRustDeskPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $desktopSignature = Get-AuthenticodeSignature -FilePath $plannedRustDeskPath
    $desktopExecutableBinding.signatureStatus = [string]$desktopSignature.Status
    if ($desktopSignature.SignerCertificate) {
        $desktopExecutableBinding.signerSubject = [string]$desktopSignature.SignerCertificate.Subject
        $desktopExecutableBinding.signerThumbprint = [string]$desktopSignature.SignerCertificate.Thumbprint
    }
    $desktopExecutableBinding.productVersion = [string](Get-Item -LiteralPath $plannedRustDeskPath).VersionInfo.ProductVersion
}
if ($config.access.desktop.enabled -and (-not $desktopExecutableBinding.exists -or $desktopExecutableBinding.signatureStatus -ne 'Valid')) {
    Add-Blocker 'RUSTDESK_EXECUTABLE_IDENTITY_REQUIRED' 'The default protected RustDesk executable must exist with a valid Authenticode signature before desktop plan approval.'
}

if ($config.compute.enabled) {
    if ($config.compute.runtime -ne 'wsl2') { Add-Blocker 'UNSUPPORTED_COMPUTE_RUNTIME' 'The Windows staging runtime must be wsl2.' }
    if ($config.compute.availability -ne 'on-demand') { Add-Blocker 'WSL_ALWAYS_ON_NOT_CLAIMED' 'This Windows pilot supports on-demand WSL compute only. Always-on pre-login inference requires the future native-Linux node.' }
    $distroPresent = @($audit.compute.distributions) -contains $config.compute.distribution
    if (-not $distroPresent) {
        if ($config.compute.install) {
            Add-Step 'install-wsl-distro' 'compute' "Install $($config.compute.distribution) without changing the existing docker-desktop distribution." $true 'approved apply and disk-space review' 'Export before manually unregistering; never auto-delete.'
        }
        else {
            Add-Warning 'COMPUTE_INSTALL_DISABLED' "The $($config.compute.distribution) distribution is absent and compute.install is false. ComputePreview remains available."
        }
    }
    Add-Step 'bootstrap-linux' 'compute' 'Install the minimal Linux toolchain and a dedicated unprivileged workload user.' $true 'distribution exists' 'Remove framework-owned packages/files or restore the exported distro snapshot.'
    if ($config.compute.resources.applyGlobalWslConfig) {
        Add-Blocker 'GLOBAL_WSL_LIMITS_REFUSED' '.wslconfig affects Docker Desktop and every WSL2 distribution. This project only generates a recommendation; apply it separately after reviewing current workloads.'
    }
    if ($config.compute.gpu.activate) {
        Add-Step 'verify-amd-matrix' 'gpu' 'Confirm the installed AMD Windows driver, WSL kernel, Ubuntu point release, and ROCm matrix match the Ryzen AI Max 390/gfx1151.' $false 'online compatibility check' 'none'
        Add-Step 'install-rocm-wsl' 'gpu' 'Install the matching AMD ROCm-for-WSL userspace stack and verify gfx1151 with rocminfo.' $true 'GPU driver and reboot approval' 'Use amdgpu-uninstall; restore the pre-change driver if needed.'
    }
    else {
        Add-Warning 'GPU_DEFERRED' 'AMD GPU activation is intentionally off. CPU/container validation can proceed first.'
    }
    Add-Step 'compute-smoke' 'compute' 'Run an isolated, networkless, read-only container proof under a unique name.' $false 'none' 'Container is removed automatically.'
}

foreach ($finding in @($audit.findings)) {
    if ($finding.Severity -eq 'WARN') { Add-Warning $finding.Code $finding.Message }
}

$planBody = [pscustomobject][ordered]@{
    planVersion = 1
    generatedUtc = [DateTime]::UtcNow.ToString('o')
    expiresUtc = [DateTime]::UtcNow.AddHours(1).ToString('o')
    machineFingerprint = $audit.machineFingerprint
    plannerUserSid = [string]$audit.host.currentUserSid
    plannerElevated = [bool]$audit.host.elevated
    configPath = $resolvedConfigPath
    nodeName = $config.nodeName
    profile = $config.profile
    sshTarget = $sshTargetBinding
    tailscaleExecutableIdentity = $audit.access.tailscale.executableIdentity
    desktopExecutable = $desktopExecutableBinding
    blockers = $blockers.ToArray()
    warnings = $warnings.ToArray()
    steps = $steps.ToArray()
    publicKeyManifest = $publicKeyManifest.ToArray()
}

$configSha256 = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
$hashBody = [pscustomobject][ordered]@{
    planVersion = $planBody.planVersion
    machineFingerprint = $planBody.machineFingerprint
    plannerUserSid = $planBody.plannerUserSid
    plannerElevated = $planBody.plannerElevated
    configSha256 = $configSha256
    nodeName = $planBody.nodeName
    profile = $planBody.profile
    sshTarget = $planBody.sshTarget
    tailscaleExecutableIdentity = $planBody.tailscaleExecutableIdentity
    desktopExecutable = $planBody.desktopExecutable
    blockers = $planBody.blockers
    warnings = $planBody.warnings
    steps = $planBody.steps
    publicKeyManifest = $planBody.publicKeyManifest
}
$canonical = $hashBody | ConvertTo-Json -Depth 10 -Compress
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $hashBytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical))
    $stateHash = ([BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
}
finally {
    $sha.Dispose()
}

$approvalBody = [pscustomobject][ordered]@{
    stateHash = $stateHash
    configSha256 = $configSha256
    plan = $planBody
}
$approvalCanonical = $approvalBody | ConvertTo-Json -Depth 12 -Compress
$approvalSha = [Security.Cryptography.SHA256]::Create()
try {
    $approvalBytes = $approvalSha.ComputeHash([Text.Encoding]::UTF8.GetBytes($approvalCanonical))
    $planHash = ([BitConverter]::ToString($approvalBytes) -replace '-', '').ToLowerInvariant()
}
finally { $approvalSha.Dispose() }

$plan = [pscustomobject][ordered]@{
    planHash = $planHash
    stateHash = $stateHash
    configSha256 = $configSha256
    plan = $planBody
}

if ([string]::IsNullOrWhiteSpace($OutputPath) -and -not $NoReport) {
    $projectRoot = Split-Path $PSScriptRoot -Parent
    $OutputPath = Join-Path $projectRoot 'reports\plan-latest.json'
}
if (-not $NoReport) {
    $directory = Split-Path $OutputPath -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $plan | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
}

if ($PassThru) { return $plan }

if ($Json) {
    $plan | ConvertTo-Json -Depth 12
}
else {
    Write-Output "EnvoyNode plan: $($steps.Count) steps, $($blockers.Count) blocker(s), $($warnings.Count) warning(s)"
    Write-Output "Plan hash: $planHash"
    foreach ($blocker in $blockers) { Write-Output "[BLOCKER] $($blocker.code): $($blocker.message)" }
    foreach ($warning in $warnings) { Write-Output "[WARN] $($warning.code): $($warning.message)" }
    Write-Output "Plan: $OutputPath"
}
