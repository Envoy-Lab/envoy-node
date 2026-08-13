[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [string]$ApprovedPlanHash,
    [string]$ApprovedPlanPath,
    [switch]$Apply,
    [switch]$AcknowledgeCurrentBootAccessProof,
    [switch]$AcknowledgeWorkloadInterruption
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:WindowsSystemDirectory = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { Join-Path $env:WINDIR 'Sysnative' } else { Join-Path $env:WINDIR 'System32' }
$script:WslExe = Join-Path $script:WindowsSystemDirectory 'wsl.exe'
$script:wslRegistration = $null

function Get-EnvoyMachineFingerprint {
    $machineGuid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$machineGuid))
        return (([BitConverter]::ToString($digest) -replace '-', '').Substring(0, 16).ToLowerInvariant())
    }
    finally { $sha.Dispose() }
}

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-NotReparsePoint {
    param([Parameter(Mandatory = $true)][string]$Path, [string]$Description = 'path')
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing the $Description because it is a reparse point: $Path"
    }
}

function Set-ExactComputeStateAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$OwnerSid,
        [Parameter(Mandatory = $true)][bool]$IsDirectory
    )
    Assert-NotReparsePoint -Path $Path -Description 'compute state path'
    $owner = New-Object Security.Principal.SecurityIdentifier($OwnerSid)
    if ($IsDirectory) {
        $security = New-Object Security.AccessControl.DirectorySecurity
    }
    else {
        $security = New-Object Security.AccessControl.FileSecurity
    }
    $security.SetOwner($owner)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sidText in @($OwnerSid, 'S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
        if ($IsDirectory) {
            $rule = New-Object Security.AccessControl.FileSystemAccessRule(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow
            )
        }
        else {
            $rule = New-Object Security.AccessControl.FileSystemAccessRule(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow
            )
        }
        $null = $security.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $security
}

function Assert-ExactComputeStateAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$OwnerSid,
        [Parameter(Mandatory = $true)][bool]$IsDirectory
    )
    if (-not (Test-Path -LiteralPath $Path)) { throw "Required compute state path is missing: $Path" }
    Assert-NotReparsePoint -Path $Path -Description 'compute state path'
    $acl = Get-Acl -LiteralPath $Path
    $actualOwner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($actualOwner -cne $OwnerSid) { throw "Compute state owner is '$actualOwner', expected '$OwnerSid': $Path" }
    if (-not $acl.AreAccessRulesProtected) { throw "Compute state ACL inheritance is enabled: $Path" }

    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $expectedSids = @($OwnerSid, 'S-1-5-18', 'S-1-5-32-544') | Sort-Object
    $actualSids = @($rules | ForEach-Object { $_.IdentityReference.Value } | Sort-Object)
    if ($rules.Count -ne 3 -or (Compare-Object $expectedSids $actualSids)) {
        throw "Compute state ACL contains an unexpected principal or rule count: $Path"
    }
    foreach ($rule in $rules) {
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            [int]$rule.FileSystemRights -ne [int][Security.AccessControl.FileSystemRights]::FullControl) {
            throw "Compute state ACL contains an unexpected inherited, deny, or non-full-control rule: $Path"
        }
        if ($IsDirectory) {
            $expectedInheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
            if ($rule.InheritanceFlags -ne $expectedInheritance -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
                throw "Compute state directory ACL inheritance flags are not exact: $Path"
            }
        }
        elseif ($rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None) {
            throw "Compute state file has inheritable ACEs: $Path"
        }
    }
}

function Initialize-ComputeStateDirectory {
    Assert-NotReparsePoint -Path $script:projectRoot -Description 'EnvoyNode project root'
    if (-not (Test-Path -LiteralPath $script:stateDir)) {
        New-Item -ItemType Directory -Path $script:stateDir | Out-Null
    }
    Set-ExactComputeStateAcl -Path $script:stateDir -OwnerSid $script:windowsOwnerSid -IsDirectory $true
    Assert-ExactComputeStateAcl -Path $script:stateDir -OwnerSid $script:windowsOwnerSid -IsDirectory $true
}

function Write-ProtectedComputeStateFile {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Text)
    Assert-ExactComputeStateAcl -Path $script:stateDir -OwnerSid $script:windowsOwnerSid -IsDirectory $true
    if (Test-Path -LiteralPath $Path) {
        Assert-ExactComputeStateAcl -Path $Path -OwnerSid $script:windowsOwnerSid -IsDirectory $false
    }
    $temporaryPath = Join-Path $script:stateDir ('.envoy-state-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $Text | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
        Set-ExactComputeStateAcl -Path $temporaryPath -OwnerSid $script:windowsOwnerSid -IsDirectory $false
        Assert-ExactComputeStateAcl -Path $temporaryPath -OwnerSid $script:windowsOwnerSid -IsDirectory $false
        if (Test-Path -LiteralPath $Path) {
            [IO.File]::Replace($temporaryPath, $Path, $null, $true)
        }
        else {
            [IO.File]::Move($temporaryPath, $Path)
        }
        Set-ExactComputeStateAcl -Path $Path -OwnerSid $script:windowsOwnerSid -IsDirectory $false
        Assert-ExactComputeStateAcl -Path $Path -OwnerSid $script:windowsOwnerSid -IsDirectory $false
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force }
    }
}

function Get-ProtectedComputeState {
    if (-not (Test-Path -LiteralPath $script:stateDir)) { return $null }
    Assert-ExactComputeStateAcl -Path $script:stateDir -OwnerSid $script:windowsOwnerSid -IsDirectory $true
    if (-not (Test-Path -LiteralPath $script:currentStatePath)) { return $null }
    Assert-ExactComputeStateAcl -Path $script:currentStatePath -OwnerSid $script:windowsOwnerSid -IsDirectory $false
    return (Get-Content -LiteralPath $script:currentStatePath -Raw | ConvertFrom-Json)
}

function Save-ComputeState {
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][bool]$CreatedByEnvoyNode,
        [string]$MarkerStatus = $null,
        [string]$Message = $null,
        [string]$DockerService = $null
    )
    $state = [pscustomobject][ordered]@{
        schemaVersion = 2
        generatedUtc = [DateTime]::UtcNow.ToString('o')
        machineFingerprint = $script:machineFingerprint
        windowsOwner = $env:USERNAME
        windowsOwnerSid = $script:windowsOwnerSid
        distribution = $script:distro
        registrationId = if ($script:wslRegistration) { [string]$script:wslRegistration.registrationId } else { $null }
        registrationBasePath = if ($script:wslRegistration) { [string]$script:wslRegistration.basePath } else { $null }
        wslVersion = if ($script:wslRegistration) { [int]$script:wslRegistration.version } else { $null }
        status = $Status
        createdByEnvoyNode = $CreatedByEnvoyNode
        managedMarker = '/etc/envoynode/managed.json'
        managedMarkerStatus = $MarkerStatus
        dockerService = $DockerService
        dedicatedEngineSmokeImage = $script:smokeImage
        gpuInstalled = $false
        message = $Message
        note = 'Journals are informational only and never authorize adoption of an unmarked distribution. Rollback never unregisters a distribution automatically.'
    }
    $json = $state | ConvertTo-Json -Depth 6
    Write-ProtectedComputeStateFile -Path $script:currentStatePath -Text $json
    $journalPath = Join-Path $script:stateDir ('compute-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.json')
    Write-ProtectedComputeStateFile -Path $journalPath -Text $json
    return $script:currentStatePath
}

function Test-WslPlatformReady {
    if (-not (Test-Path -LiteralPath $script:WslExe -PathType Leaf)) { return $false }
    $prior = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $null = & $script:WslExe --status 2>&1
        return ($LASTEXITCODE -eq 0)
    }
    finally { $ErrorActionPreference = $prior }
}

function Get-WslDistributions {
    if (-not (Test-WslPlatformReady)) { return @() }
    $prior = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $text = ((& $script:WslExe --list --quiet 2>$null | Out-String) -replace "`0", '')
        if ($LASTEXITCODE -ne 0) { return @() }
    }
    finally { $ErrorActionPreference = $prior }
    return @($text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-WslRegistration {
    param([Parameter(Mandatory = $true)][string]$Distribution)
    $lxssRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
    if (-not (Test-Path -LiteralPath $lxssRoot)) { return $null }
    foreach ($key in @(Get-ChildItem -LiteralPath $lxssRoot -ErrorAction Stop)) {
        $record = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
        if ([string]$record.DistributionName -ieq $Distribution) {
            return [pscustomobject][ordered]@{
                registrationId = [string]$key.PSChildName
                distribution = [string]$record.DistributionName
                basePath = [string]$record.BasePath
                version = [int]$record.Version
            }
        }
    }
    return $null
}

function Assert-Wsl2Registration {
    param([Parameter(Mandatory = $true)][string]$Distribution)
    $registration = Get-WslRegistration -Distribution $Distribution
    if (-not $registration) { throw "Could not bind '$Distribution' to a live per-user WSL registration." }
    if ($registration.version -ne 2) { throw "The selected distribution '$Distribution' is WSL version $($registration.version), not required version 2." }
    if ([string]::IsNullOrWhiteSpace($registration.basePath)) { throw "The selected distribution '$Distribution' has no conclusive registration base path." }
    return $registration
}

function Invoke-WslChecked {
    param([string]$Distribution, [string[]]$ArgumentList)
    $prior = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $text = (& $script:WslExe -d $Distribution -u root -- @ArgumentList 2>&1 | Out-String).Trim()
        $code = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $prior }
    if ($code -ne 0) { throw "WSL command failed with exit code $code. $text" }
    return $text
}

function Invoke-WslScriptChecked {
    param([string]$Distribution, [string]$ScriptText)
    if ($Distribution -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { throw 'Unsafe WSL distribution name passed to the script transport.' }
    $normalizedScript = ($ScriptText -replace "`r`n?", "`n")
    $scriptBytes = [Text.Encoding]::ASCII.GetBytes($normalizedScript)
    if ([Text.Encoding]::ASCII.GetString($scriptBytes) -cne $normalizedScript) { throw 'WSL script transport accepts ASCII input only.' }

    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $script:WslExe
    $startInfo.Arguments = "-d $Distribution -u root -- bash -s --"
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $startInfo
    $started = $false
    try {
        $started = $process.Start()
        if (-not $started) { throw 'Could not start wsl.exe for script transport.' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.BaseStream.Write($scriptBytes, 0, $scriptBytes.Length)
        $process.StandardInput.BaseStream.Flush()
        $process.StandardInput.BaseStream.Close()
        $process.WaitForExit()
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        $code = $process.ExitCode
    }
    finally {
        if ($started -and -not $process.HasExited) { try { $process.Kill() } catch { } }
        $process.Dispose()
    }
    $text = (($stdout.TrimEnd() + "`n" + $stderr.TrimEnd()).Trim())
    if ($code -ne 0) { throw "WSL script failed with exit code $code. $text" }
    return $text
}

function Get-ActiveComputeContainerIds {
    $probe = @'
set -euo pipefail
unset DOCKER_HOST DOCKER_CONTEXT
if command -v docker >/dev/null 2>&1; then
  if { command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet docker.service 2>/dev/null; } || { command -v pgrep >/dev/null 2>&1 && pgrep -x dockerd >/dev/null 2>&1; }; then
    docker --host unix:///run/docker.sock ps --no-trunc -q
  fi
fi
'@
    $text = Invoke-WslScriptChecked -Distribution $script:distro -ScriptText $probe
    if ([string]::IsNullOrWhiteSpace($text)) { return @() }
    $ids = @($text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    foreach ($id in $ids) {
        if ($id -notmatch '^[0-9a-f]{12,64}$') { throw "Active-container inspection returned unexpected output: $id" }
    }
    return $ids
}

function Assert-ExactManagedMarker {
    param(
        [Parameter(Mandatory = $true)][string]$JsonText,
        [Parameter(Mandatory = $true)][string[]]$AllowedStatus
    )
    try { $marker = $JsonText | ConvertFrom-Json }
    catch { throw "The EnvoyNode marker is not valid JSON: $($_.Exception.Message)" }
    $expectedProperties = @('machineFingerprint', 'managedBy', 'schemaVersion', 'status', 'windowsOwnerSid') | Sort-Object
    $actualProperties = @($marker.PSObject.Properties.Name | Sort-Object)
    if (Compare-Object -ReferenceObject $expectedProperties -DifferenceObject $actualProperties -CaseSensitive) { throw 'The EnvoyNode marker schema is not exact.' }
    if ($marker.schemaVersion -ne 1 -or [string]$marker.managedBy -cne 'EnvoyNode' -or
        [string]$marker.machineFingerprint -cne $script:machineFingerprint -or
        [string]$marker.windowsOwnerSid -cne $script:windowsOwnerSid -or
        $AllowedStatus -cnotcontains [string]$marker.status) {
        throw 'The EnvoyNode marker does not exactly match this machine, Windows owner, or allowed lifecycle status.'
    }
    $canonical = [pscustomobject][ordered]@{
        schemaVersion = 1
        managedBy = 'EnvoyNode'
        machineFingerprint = $script:machineFingerprint
        windowsOwnerSid = $script:windowsOwnerSid
        status = [string]$marker.status
    } | ConvertTo-Json -Compress
    if ($JsonText.Trim() -cne $canonical) { throw 'The EnvoyNode marker is valid JSON but is not the exact canonical marker.' }
    return $marker
}

function Read-EnvoyManagedMarker {
    param([Parameter(Mandatory = $true)][string[]]$AllowedStatus)
    $readScript = @'
set -euo pipefail
export LC_ALL=C
test -d /etc/envoynode
test ! -L /etc/envoynode
test "$(stat -c '%F|%u|%g|%a' /etc/envoynode)" = 'directory|0|0|700'
test -f /etc/envoynode/managed.json
test ! -L /etc/envoynode/managed.json
test "$(stat -c '%F|%u|%g|%a' /etc/envoynode/managed.json)" = 'regular file|0|0|600'
cat /etc/envoynode/managed.json
'@
    $json = Invoke-WslScriptChecked -Distribution $script:distro -ScriptText $readScript
    return (Assert-ExactManagedMarker -JsonText $json -AllowedStatus $AllowedStatus)
}

function Write-EnvoyManagedMarker {
    param([Parameter(Mandatory = $true)][ValidateSet('bootstrap-in-progress', 'ready')][string]$Status)
    $markerJson = [pscustomobject][ordered]@{
        schemaVersion = 1
        managedBy = 'EnvoyNode'
        machineFingerprint = $script:machineFingerprint
        windowsOwnerSid = $script:windowsOwnerSid
        status = $Status
    } | ConvertTo-Json -Compress
    if ($markerJson -match "'") { throw 'Unexpected unsafe character in generated marker JSON.' }
    $writeTemplate = @'
set -euo pipefail
export LC_ALL=C
. /etc/os-release
test "$ID" = 'ubuntu'
case "$VERSION_ID" in 24.04*) ;; *) echo "Expected Ubuntu 24.04, found $VERSION_ID" >&2; exit 42 ;; esac
if [ -e /etc/envoynode ] || [ -L /etc/envoynode ]; then
  test -d /etc/envoynode
  test ! -L /etc/envoynode
fi
install -d -o root -g root -m 0700 /etc/envoynode
if [ -e /etc/envoynode/managed.json ] || [ -L /etc/envoynode/managed.json ]; then
  test -f /etc/envoynode/managed.json
  test ! -L /etc/envoynode/managed.json
fi
umask 077
tmp="$(mktemp /etc/envoynode/.managed.json.XXXXXX)"
trap 'rm -f -- "$tmp"' EXIT
printf '%s\n' '__MARKER_JSON__' > "$tmp"
chown root:root "$tmp"
chmod 0600 "$tmp"
mv -fT -- "$tmp" /etc/envoynode/managed.json
trap - EXIT
'@
    $writeScript = $writeTemplate.Replace('__MARKER_JSON__', $markerJson)
    $null = Invoke-WslScriptChecked -Distribution $script:distro -ScriptText $writeScript
    return (Read-EnvoyManagedMarker -AllowedStatus @($Status))
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "Configuration file not found: $ConfigPath" }
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$compute = $config.compute
$script:machineFingerprint = Get-EnvoyMachineFingerprint
$script:windowsOwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$script:distro = [string]$compute.distribution
$linuxUser = [string]$compute.linuxUser
$configuredWindowsOwner = [string]$config.access.ssh.targetUser
$script:smokeImage = 'docker.io/library/hello-world@sha256:7f4da0fc94bcece205a8c0b6f4d11c8196924654ffe5c4d1aa439b7f632048b2'
if ([string]::IsNullOrWhiteSpace($configuredWindowsOwner)) { $configuredWindowsOwner = $env:USERNAME }

if ($script:distro -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { throw 'Unsafe WSL distribution name.' }
if ($script:distro -match '^docker-desktop(?:-data)?$') { throw 'The Docker Desktop distributions are protected and cannot be used as the EnvoyNode compute target.' }
if ($linuxUser -notmatch '^[a-z_][a-z0-9_-]{0,30}$') { throw 'Unsafe Linux user name.' }
if ($linuxUser -in @('root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup', 'list', 'irc', 'gnats', 'nobody', 'systemd-network', 'systemd-resolve', 'messagebus', 'syslog', '_apt', 'tss', 'uuidd', 'tcpdump', 'sshd', 'landscape', 'pollinate')) {
    throw "compute.linuxUser '$linuxUser' is reserved; choose a dedicated unprivileged account name."
}
if ($compute.runtime -ne 'wsl2') { throw 'This bootstrap supports wsl2 only.' }
if ($compute.containerEngine -ne 'docker-engine') { throw 'This bootstrap supports the dedicated docker-engine profile only.' }
if (-not $compute.enabled) { throw 'compute.enabled is false.' }
if ($compute.resources.applyGlobalWslConfig) { throw 'This script never applies global .wslconfig limits because they also affect Docker Desktop and every WSL2 distribution.' }
if ($compute.gpu.activate -or $compute.gpu.changeVariableGraphicsMemory) { throw 'GPU drivers, ROCm, and graphics-memory changes require the separate GPU activation window; leave both GPU mutation flags false for ComputeBootstrap.' }
if ($configuredWindowsOwner -ine $env:USERNAME) {
    throw "WSL distributions are per-Windows-user. Run ComputeBootstrap while signed in as the configured SSH target '$configuredWindowsOwner'; current user is '$env:USERNAME'."
}

$requestedMemoryGB = [int]$compute.resources.memoryGB
$requestedProcessors = [int]$compute.resources.processors
$requestedSwapGB = [int]$compute.resources.swapGB
if ($requestedMemoryGB -lt 4) { throw 'compute.resources.memoryGB must be at least 4.' }
if ($requestedProcessors -lt 1) { throw 'compute.resources.processors must be at least 1.' }
if ($requestedSwapGB -lt 0) { throw 'compute.resources.swapGB cannot be negative.' }
$hostComputer = Get-CimInstance Win32_ComputerSystem
$hostProcessor = Get-CimInstance Win32_Processor | Select-Object -First 1
$hostVisibleMemoryGB = [math]::Floor($hostComputer.TotalPhysicalMemory / 1GB)
if ($requestedMemoryGB -gt ($hostVisibleMemoryGB - 8)) { throw "Requested WSL memory leaves less than 8 GB visible host headroom ($hostVisibleMemoryGB GB visible)." }
if ($requestedProcessors -gt $hostProcessor.NumberOfLogicalProcessors) { throw 'Requested WSL processor count exceeds the host logical processor count.' }

$script:projectRoot = Split-Path $PSScriptRoot -Parent
$generatedDir = Join-Path $script:projectRoot 'generated'
$script:stateDir = Join-Path $script:projectRoot 'state'
$script:currentStatePath = Join-Path $script:stateDir 'compute-current.json'
$recommendationPath = Join-Path $generatedDir 'wslconfig.recommended'
$wslConfigRecommendation = @"
# Recommendation only. This file is NOT applied automatically because .wslconfig
# affects Docker Desktop and every WSL2 distribution owned by this Windows user.
[wsl2]
memory=$($compute.resources.memoryGB)GB
processors=$($compute.resources.processors)
swap=$($compute.resources.swapGB)GB
networkingMode=nat
localhostForwarding=true
firewall=true
dnsTunneling=true
autoProxy=true
nestedVirtualization=false
"@

$wslPlatformReady = Test-WslPlatformReady
$existing = if ($wslPlatformReady) { @(Get-WslDistributions) } else { @() }
$distroExists = $existing -contains $script:distro
$registrationPreview = if ($distroExists) { Get-WslRegistration -Distribution $script:distro } else { $null }
$priorState = $null
if (Test-Path -LiteralPath $script:stateDir) {
    $priorState = Get-ProtectedComputeState
}

$preview = [pscustomobject][ordered]@{
    distribution = $script:distro
    wslPlatformReady = $wslPlatformReady
    distributionExists = $distroExists
    distributionVersion = if ($registrationPreview) { $registrationPreview.version } else { $null }
    distributionManagedByEnvoyNode = if ($distroExists) { 'deferred-until-approved-apply' } else { $false }
    ownershipProbeLaunchesDistribution = $false
    journalCanAuthorizeAdoption = $false
    priorState = if ($priorState) { $priorState.status } else { $null }
    windowsOwner = $env:USERNAME
    linuxUser = $linuxUser
    actions = @(
        if (-not $wslPlatformReady) { 'Stop: install and update the WSL2 platform separately, then complete any required reboot.' }
        elseif (-not $distroExists) { "Install $($script:distro) without launching its interactive first-run UI; require a live version-2 registration and write an exact root-owned marker immediately." }
        else { 'After approved apply, launch only the selected distribution and require its exact machine-bound marker; never trust a journal to adopt it.' }
        'Create or validate a dedicated locked, non-system Linux user.'
        'Restart only this distribution so systemd becomes PID 1.'
        'Install Docker Engine and Compose V2, then run a pinned, isolated container proof.'
        'Do not touch docker-desktop, existing host containers, global .wslconfig, ROCm, VGM, firmware, or Windows drivers.'
    )
    globalWslRecommendation = $recommendationPath
    recommendationWritten = $false
    gpuActivationDeferred = [bool](-not $compute.gpu.activate)
    requiresCurrentBootAccessProofAcknowledgment = $true
}

if (-not $Apply) { $preview | ConvertTo-Json -Depth 7; return }
if (Test-IsElevated) { throw 'ComputeBootstrap must run from a normal, non-elevated PowerShell window owned by the configured SSH/WSL account.' }
& (Join-Path $PSScriptRoot 'Assert-EnvoyPlanApproval.ps1') -Action 'ComputeBootstrap' -ConfigPath $ConfigPath -ApprovedPlanHash $ApprovedPlanHash -ApprovedPlanPath $ApprovedPlanPath
if ($config.safety.requireSecondDeviceProof -ne $true -or -not $AcknowledgeCurrentBootAccessProof) {
    throw 'ComputeBootstrap follows the access layer. Pass -AcknowledgeCurrentBootAccessProof only after AccessAcceptRebootProof has accepted a fresh second-device key-only proof for the current Windows boot.'
}
if (-not $compute.install) { throw 'compute.install is false. Copy the example config to config/node.local.json, review it, and opt in before applying.' }
if (-not $wslPlatformReady) { throw 'The WSL2 platform is not operational. Install/update WSL separately, reboot if required, and return only after wsl.exe --status succeeds.' }
if ((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
    throw 'Windows reports a pending reboot. Complete it with local recovery available before creating the compute distribution.'
}
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"
if (($disk.FreeSpace / 1GB) -lt 40) { throw 'At least 40 GB free is required before creating the compute distribution.' }
if (-not $PSCmdlet.ShouldProcess($script:distro, 'Create or resume the exactly marked WSL2 compute environment')) { return }

if (-not (Test-Path -LiteralPath $generatedDir)) { New-Item -ItemType Directory -Path $generatedDir | Out-Null }
$wslConfigRecommendation | Set-Content -LiteralPath $recommendationPath -Encoding UTF8
Initialize-ComputeStateDirectory

# Re-read inventory after approval/confirmation. No distribution was launched by preview.
$existing = @(Get-WslDistributions)
$distroExists = $existing -contains $script:distro
$createdByEnvoyNode = $false
if (-not $distroExists) {
    $null = Save-ComputeState -Status 'installing-distribution' -CreatedByEnvoyNode $true -Message 'Registration command is about to run; this journal cannot authorize a future unmarked distribution.'
    & $script:WslExe --install --distribution $script:distro --no-launch
    $installCode = $LASTEXITCODE
    $existing = @(Get-WslDistributions)
    $distroExists = $existing -contains $script:distro
    if (-not $distroExists) {
        $null = Save-ComputeState -Status 'distribution-install-pending-manual-recovery' -CreatedByEnvoyNode $true -Message "WSL install exit code $installCode; no registration exists. If an unmarked same-name distribution later appears, EnvoyNode will refuse to adopt it."
        throw 'The distribution is not registered. Complete any required reboot, then retry installation only after confirming no unmarked same-name distribution exists; journals never authorize adoption.'
    }
    $script:wslRegistration = Assert-Wsl2Registration -Distribution $script:distro
    try {
        $null = Write-EnvoyManagedMarker -Status 'bootstrap-in-progress'
        $null = Save-ComputeState -Status 'distribution-created-and-marked' -CreatedByEnvoyNode $true -MarkerStatus 'bootstrap-in-progress' -Message 'The new version-2 registration has an exact root-owned marker.'
    }
    catch {
        $null = Save-ComputeState -Status 'distribution-created-marker-failed' -CreatedByEnvoyNode $true -Message $_.Exception.Message
        throw
    }
    if ($installCode -ne 0) {
        $null = Save-ComputeState -Status 'distribution-created-marked-install-error' -CreatedByEnvoyNode $true -MarkerStatus 'bootstrap-in-progress' -Message "WSL returned exit code $installCode after registration; the exact marker permits a safe reviewed rerun."
        throw "WSL returned exit code $installCode after creating and marking the distribution. Rerun after reviewing the recorded state."
    }
    $createdByEnvoyNode = $true
}
else {
    $script:wslRegistration = Assert-Wsl2Registration -Distribution $script:distro
    try {
        $null = Read-EnvoyManagedMarker -AllowedStatus @('bootstrap-in-progress', 'ready')
    }
    catch {
        throw "The existing distribution '$($script:distro)' lacks the exact root-owned EnvoyNode marker for this machine and owner. Refusing to adopt it; local journals are never ownership proof. $($_.Exception.Message)"
    }
    $createdByEnvoyNode = $true
}

# Refresh the exact marker before any user, configuration, package, or service mutation.
$null = Write-EnvoyManagedMarker -Status 'bootstrap-in-progress'
$null = Save-ComputeState -Status 'marker-written-restart-required' -CreatedByEnvoyNode $createdByEnvoyNode -MarkerStatus 'bootstrap-in-progress' -Message 'Exact ownership marker is committed before Linux mutations.'

$stageTemplate = @'
set -euo pipefail
export LC_ALL=C
. /etc/os-release
test "$ID" = 'ubuntu'
case "$VERSION_ID" in 24.04*) ;; *) echo "Expected Ubuntu 24.04, found $VERSION_ID" >&2; exit 42 ;; esac
if [ -e '/home/__LINUX_USER__' ] || [ -L '/home/__LINUX_USER__' ]; then
  test -d '/home/__LINUX_USER__'
  test ! -L '/home/__LINUX_USER__'
fi
if ! id -u '__LINUX_USER__' >/dev/null 2>&1; then
  useradd --create-home --user-group --shell /bin/bash '__LINUX_USER__'
  passwd -l '__LINUX_USER__' >/dev/null
fi
uid="$(id -u '__LINUX_USER__')"
test "$uid" -ge 1000
test "$uid" -ne 65534
entry="$(getent passwd '__LINUX_USER__')"
IFS=: read -r account _ _ _ _ home shell <<EOF
$entry
EOF
test "$account" = '__LINUX_USER__'
test "$home" = '/home/__LINUX_USER__'
test "$shell" = '/bin/bash'
password_state="$(passwd -S '__LINUX_USER__' | awk '{print $2}')"
case "$password_state" in L|LK) ;; *) echo 'The compute account must have a locked password.' >&2; exit 43 ;; esac
for group in $(id -nG '__LINUX_USER__'); do
  case "$group" in root|sudo|wheel|adm|docker) echo "Compute account belongs to privileged group $group" >&2; exit 44 ;; esac
done
if command -v sudo >/dev/null 2>&1 && sudo -n -l -U '__LINUX_USER__' >/dev/null 2>&1; then
  echo 'The compute account has a direct sudoers grant.' >&2
  exit 45
fi
primary_group="$(id -gn '__LINUX_USER__')"
if [ -e '/home/__LINUX_USER__' ] || [ -L '/home/__LINUX_USER__' ]; then
  test -d '/home/__LINUX_USER__'
  test ! -L '/home/__LINUX_USER__'
fi
install -d -o '__LINUX_USER__' -g "$primary_group" -m 0750 '/home/__LINUX_USER__'
if [ -e /etc/wsl.conf ] || [ -L /etc/wsl.conf ]; then
  test -f /etc/wsl.conf
  test ! -L /etc/wsl.conf
fi
tmp="$(mktemp /etc/.wsl.conf.envoy.XXXXXX)"
trap 'rm -f -- "$tmp"' EXIT
printf '%s\n' '[boot]' 'systemd=true' '[user]' 'default=__LINUX_USER__' '[automount]' 'enabled=false' '[interop]' 'enabled=false' 'appendWindowsPath=false' > "$tmp"
restart_required=0
if ! test -f /etc/wsl.conf || test -L /etc/wsl.conf || ! cmp -s -- "$tmp" /etc/wsl.conf || [ "$(stat -c '%u|%g|%a' /etc/wsl.conf)" != '0|0|644' ]; then
  restart_required=1
fi
chown root:root "$tmp"
chmod 0644 "$tmp"
mv -fT -- "$tmp" /etc/wsl.conf
trap - EXIT
if mountpoint -q /mnt/c 2>/dev/null || [ -e /proc/sys/fs/binfmt_misc/WSLInterop ]; then
  restart_required=1
fi
if [ "$restart_required" -eq 1 ]; then printf '%s\n' 'restart-required'; else printf '%s\n' 'restart-not-required'; fi
'@
$stageScript = $stageTemplate.Replace('__LINUX_USER__', $linuxUser)
try {
    $stageResult = Invoke-WslScriptChecked -Distribution $script:distro -ScriptText $stageScript
}
catch {
    $null = Save-ComputeState -Status 'bootstrap-failed-before-restart' -CreatedByEnvoyNode $createdByEnvoyNode -MarkerStatus 'bootstrap-in-progress' -Message $_.Exception.Message
    throw
}

$pidOne = ''
try { $pidOne = Invoke-WslChecked -Distribution $script:distro -ArgumentList @('ps', '-p', '1', '-o', 'comm=') } catch { }
if ($pidOne -ne 'systemd' -or $stageResult -match '(?m)^restart-required$') {
    $runningContainers = @(Get-ActiveComputeContainerIds)
    if ($runningContainers.Count -gt 0 -and -not $AcknowledgeWorkloadInterruption) {
        throw 'Restarting this managed distribution would interrupt running containers. Stop them cleanly or pass -AcknowledgeWorkloadInterruption after review.'
    }
    & $script:WslExe --terminate $script:distro
    if ($LASTEXITCODE -ne 0) { throw "Could not terminate $($script:distro) to activate systemd." }
    $pidOne = Invoke-WslChecked -Distribution $script:distro -ArgumentList @('ps', '-p', '1', '-o', 'comm=')
    if ($pidOne -ne 'systemd') {
        $null = Save-ComputeState -Status 'systemd-restart-failed' -CreatedByEnvoyNode $createdByEnvoyNode -MarkerStatus 'bootstrap-in-progress' -Message "PID 1 is '$pidOne', not systemd."
        throw "systemd did not become PID 1 after the distribution restart (observed '$pidOne')."
    }
}

$runningContainersBeforePackages = @(Get-ActiveComputeContainerIds)
if ($runningContainersBeforePackages.Count -gt 0 -and -not $AcknowledgeWorkloadInterruption) {
    throw 'Package and Docker service maintenance may restart the engine and interrupt active compute containers. Stop them cleanly or pass -AcknowledgeWorkloadInterruption after review.'
}

$bootstrapSmokeName = 'envoy-compute-bootstrap-' + ([Guid]::NewGuid().ToString('N').Substring(0, 12))
$packageTemplate = @'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
unset DOCKER_HOST DOCKER_CONTEXT
dpkg --configure -a
apt-get update
apt-get install -y ca-certificates curl git iproute2 jq python3 python3-pip python3-venv docker.io docker-compose-v2
systemctl enable --now docker.service >/dev/null
systemctl is-enabled --quiet docker.service
systemctl is-active --quiet docker.service
docker --host unix:///run/docker.sock compose version >/dev/null
docker --host unix:///run/docker.sock pull docker.io/library/hello-world@sha256:7f4da0fc94bcece205a8c0b6f4d11c8196924654ffe5c4d1aa439b7f632048b2 >/dev/null
docker --host unix:///run/docker.sock run --rm --name '__SMOKE_CONTAINER__' --label io.envoynode.managed=true --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 32 --memory 64m --cpus 0.5 --user 65534:65534 docker.io/library/hello-world@sha256:7f4da0fc94bcece205a8c0b6f4d11c8196924654ffe5c4d1aa439b7f632048b2 >/dev/null
'@
$packageScript = $packageTemplate.Replace('__SMOKE_CONTAINER__', $bootstrapSmokeName)
try {
    $null = Save-ComputeState -Status 'installing-packages' -CreatedByEnvoyNode $createdByEnvoyNode -MarkerStatus 'bootstrap-in-progress' -Message 'Package installation and dedicated-engine proof are in progress.'
    $null = Invoke-WslScriptChecked -Distribution $script:distro -ScriptText $packageScript
    $enabledState = Invoke-WslChecked -Distribution $script:distro -ArgumentList @('systemctl', 'is-enabled', 'docker.service')
    $activeState = Invoke-WslChecked -Distribution $script:distro -ArgumentList @('systemctl', 'is-active', 'docker.service')
    if ($enabledState -ne 'enabled' -or $activeState -ne 'active') { throw "Docker service state is enabled='$enabledState', active='$activeState'." }
    $null = Write-EnvoyManagedMarker -Status 'ready'
}
catch {
    $null = Save-ComputeState -Status 'bootstrap-failed-resumable' -CreatedByEnvoyNode $createdByEnvoyNode -MarkerStatus 'bootstrap-in-progress' -Message $_.Exception.Message
    Write-Warning 'Bootstrap stopped in an exactly marked, resumable distribution. It was not unregistered or deleted.'
    throw
}

$statePath = Save-ComputeState -Status 'ready-on-demand' -CreatedByEnvoyNode $createdByEnvoyNode -MarkerStatus 'ready' -DockerService 'enabled,active' -Message 'Dedicated engine passed the pinned isolated bootstrap smoke test; strict compute verification is next.'
try {
    $computeProof = & (Join-Path $PSScriptRoot 'Test-EnvoyCompute.ps1') -ConfigPath $ConfigPath -PassThru -NoReport
    if (-not $computeProof.passed) { throw 'Strict dedicated-engine verification returned a failed report.' }
}
catch {
    $null = Save-ComputeState -Status 'bootstrap-failed-strict-verification' -CreatedByEnvoyNode $createdByEnvoyNode -MarkerStatus 'ready' -DockerService 'enabled,active' -Message $_.Exception.Message
    throw
}

Write-Output "Compute bootstrap complete and resumable state is ready. State: $statePath"
Write-Output 'This proves on-demand WSL compute, not pre-login 24/7 inference. Windows SSH remains the recovery/control plane.'
Write-Output 'ROCm/VGM remain unchanged and require a separate compatibility/reboot approval.'
