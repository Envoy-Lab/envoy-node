[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [string]$Destination,
    [string]$ApprovedPlanHash,
    [string]$ApprovedPlanPath,
    [switch]$Apply,
    [switch]$AcknowledgeWorkloadInterruption,
    [switch]$AcknowledgeActiveComputeContainers
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:WindowsSystemDirectory = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { Join-Path $env:WINDIR 'Sysnative' } else { Join-Path $env:WINDIR 'System32' }
$script:WslExe = Join-Path $script:WindowsSystemDirectory 'wsl.exe'

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
    if (-not (Test-Path -LiteralPath $Path)) { throw "Required $Description is missing: $Path" }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Refusing the $Description because it is a reparse point: $Path" }
}

function Assert-ExactComputeStateAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$OwnerSid,
        [Parameter(Mandatory = $true)][bool]$IsDirectory
    )
    Assert-NotReparsePoint -Path $Path -Description 'compute state path'
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $OwnerSid -or -not $acl.AreAccessRulesProtected) {
        throw "Compute state owner or inheritance protection is not exact: $Path"
    }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $expectedSids = @($OwnerSid, 'S-1-5-18', 'S-1-5-32-544') | Sort-Object
    $actualSids = @($rules | ForEach-Object { $_.IdentityReference.Value } | Sort-Object)
    if ($rules.Count -ne 3 -or (Compare-Object $expectedSids $actualSids)) { throw "Compute state ACL principals are not exact: $Path" }
    foreach ($rule in $rules) {
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            [int]$rule.FileSystemRights -ne [int][Security.AccessControl.FileSystemRights]::FullControl) {
            throw "Compute state ACL contains an unexpected rule: $Path"
        }
        if ($IsDirectory) {
            $expectedInheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
            if ($rule.InheritanceFlags -ne $expectedInheritance -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { throw "Compute state directory inheritance flags are not exact: $Path" }
        }
        elseif ($rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None) { throw "Compute state file has inheritable ACEs: $Path" }
    }
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

function Get-WslNames {
    $text = ((& $script:WslExe --list --quiet 2>$null | Out-String) -replace "`0", '')
    if ($LASTEXITCODE -ne 0) { throw 'Could not inventory WSL distributions.' }
    return @($text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-WslRunningNames {
    $text = ((& $script:WslExe --list --running --quiet 2>$null | Out-String) -replace "`0", '')
    if ($LASTEXITCODE -ne 0) { throw 'Could not inventory running WSL distributions.' }
    return @($text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-WslRegistration {
    param([Parameter(Mandatory = $true)][string]$Distribution)
    $root = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
    if (-not (Test-Path -LiteralPath $root)) { return $null }
    foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
        $record = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
        if ([string]$record.DistributionName -ieq $Distribution) {
            return [pscustomobject][ordered]@{
                registrationId = [string]$key.PSChildName
                basePath = [string]$record.BasePath
                version = [int]$record.Version
            }
        }
    }
    return $null
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

function Assert-ExactManagedMarker {
    param([Parameter(Mandatory = $true)][string]$JsonText)
    try { $marker = $JsonText | ConvertFrom-Json }
    catch { throw "The EnvoyNode marker is not valid JSON: $($_.Exception.Message)" }
    $expected = @('machineFingerprint', 'managedBy', 'schemaVersion', 'status', 'windowsOwnerSid') | Sort-Object
    $actual = @($marker.PSObject.Properties.Name | Sort-Object)
    if (Compare-Object -ReferenceObject $expected -DifferenceObject $actual -CaseSensitive) { throw 'The EnvoyNode marker schema is not exact.' }
    if ($marker.schemaVersion -ne 1 -or [string]$marker.managedBy -cne 'EnvoyNode' -or
        [string]$marker.machineFingerprint -cne $script:machineFingerprint -or
        [string]$marker.windowsOwnerSid -cne $script:windowsOwnerSid -or
        [string]$marker.status -cne 'ready') {
        throw 'The EnvoyNode marker does not exactly match this machine, owner, and ready state.'
    }
    $canonical = [pscustomobject][ordered]@{ schemaVersion = 1; managedBy = 'EnvoyNode'; machineFingerprint = $script:machineFingerprint; windowsOwnerSid = $script:windowsOwnerSid; status = 'ready' } | ConvertTo-Json -Compress
    if ($JsonText.Trim() -cne $canonical) { throw 'The EnvoyNode marker is valid JSON but is not the exact canonical marker.' }
}

function Assert-LiveManagedMarker {
    $probe = @'
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
    $markerJson = Invoke-WslScriptChecked -Distribution $script:distro -ScriptText $probe
    Assert-ExactManagedMarker -JsonText $markerJson
}

if (-not $Apply) {
    throw 'Export-EnvoyCompute.ps1 is mutating and requires the explicit -Apply switch, even when invoked directly.'
}
if (Test-IsElevated) {
    throw 'ExportCompute must run from a normal, non-elevated PowerShell window owned by the configured WSL account.'
}
if (-not $AcknowledgeWorkloadInterruption) {
    throw 'Export requires -AcknowledgeWorkloadInterruption because it may terminate the selected WSL distribution.'
}
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "Configuration file not found: $ConfigPath" }
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$script:distro = [string]$config.compute.distribution
if ($script:distro -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { throw 'Unsafe WSL distribution name.' }
if ($script:distro -match '^docker-desktop(?:-data)?$') { throw 'The Docker Desktop distributions are protected and can never be an EnvoyNode export target.' }
if (-not (Test-WslPlatformReady)) { throw 'The WSL2 platform is not operational.' }

$projectRoot = Split-Path $PSScriptRoot -Parent
$script:machineFingerprint = Get-EnvoyMachineFingerprint
$script:windowsOwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$stateDir = Join-Path $projectRoot 'state'
$computeStatePath = Join-Path $stateDir 'compute-current.json'
Assert-ExactComputeStateAcl -Path $stateDir -OwnerSid $script:windowsOwnerSid -IsDirectory $true
Assert-ExactComputeStateAcl -Path $computeStatePath -OwnerSid $script:windowsOwnerSid -IsDirectory $false
$computeStateHash = (Get-FileHash -LiteralPath $computeStatePath -Algorithm SHA256).Hash
$computeState = Get-Content -LiteralPath $computeStatePath -Raw | ConvertFrom-Json

$names = @(Get-WslNames)
if ($names -notcontains $script:distro) { throw "WSL distribution not found: $($script:distro)" }
$registration = Get-WslRegistration -Distribution $script:distro
if (-not $registration -or $registration.version -ne 2 -or [string]::IsNullOrWhiteSpace($registration.basePath)) {
    throw "The selected distribution '$($script:distro)' is not conclusively registered as WSL version 2."
}
if ($computeState.schemaVersion -ne 2 -or $computeState.machineFingerprint -cne $script:machineFingerprint -or
    $computeState.windowsOwnerSid -cne $script:windowsOwnerSid -or $computeState.distribution -cne $script:distro -or
    $computeState.createdByEnvoyNode -isnot [bool] -or -not [bool]$computeState.createdByEnvoyNode -or $computeState.status -cne 'ready-on-demand' -or
    $computeState.managedMarkerStatus -cne 'ready' -or $computeState.wslVersion -ne 2 -or
    $computeState.registrationId -cne $registration.registrationId -or
    $computeState.registrationBasePath -cne $registration.basePath) {
    throw 'Protected compute state does not exactly match this machine, owner, ready lifecycle, and live WSL2 registration.'
}

if ([string]::IsNullOrWhiteSpace($Destination)) {
    $exportDir = Join-Path $projectRoot 'exports'
    $Destination = Join-Path $exportDir ($script:distro + '-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '.tar')
}
elseif (-not [IO.Path]::IsPathRooted($Destination)) {
    $Destination = [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Destination))
}
if (Test-Path -LiteralPath $Destination) { throw "Refusing to overwrite existing export: $Destination" }
$manifestPath = $Destination + '.manifest.json'
if (Test-Path -LiteralPath $manifestPath) { throw "Refusing to overwrite existing export manifest: $manifestPath" }
$destinationParent = Split-Path $Destination -Parent
if ($destinationParent -and (Test-Path -LiteralPath $destinationParent)) { Assert-NotReparsePoint -Path $destinationParent -Description 'export destination directory' }
elseif ($destinationParent -and $destinationParent -ne (Join-Path $projectRoot 'exports')) { throw "Destination directory does not exist: $destinationParent" }

& (Join-Path $PSScriptRoot 'Assert-EnvoyPlanApproval.ps1') -Action 'ExportCompute' -ConfigPath $ConfigPath -ApprovedPlanHash $ApprovedPlanHash -ApprovedPlanPath $ApprovedPlanPath
if (-not $PSCmdlet.ShouldProcess($script:distro, "Export the selected WSL2 distribution to $Destination")) { return }

Assert-ExactComputeStateAcl -Path $stateDir -OwnerSid $script:windowsOwnerSid -IsDirectory $true
Assert-ExactComputeStateAcl -Path $computeStatePath -OwnerSid $script:windowsOwnerSid -IsDirectory $false
if ((Get-FileHash -LiteralPath $computeStatePath -Algorithm SHA256).Hash -cne $computeStateHash) { throw 'Protected compute state changed after plan approval; review a fresh export plan.' }
$liveNames = @(Get-WslNames)
$liveRegistration = Get-WslRegistration -Distribution $script:distro
if ($liveNames -notcontains $script:distro -or -not $liveRegistration -or $liveRegistration.version -ne 2 -or
    $liveRegistration.registrationId -cne $registration.registrationId -or $liveRegistration.basePath -cne $registration.basePath) {
    throw 'The selected WSL2 registration changed after plan approval; refusing to export by name.'
}
$registration = $liveRegistration

$runningNames = @(Get-WslRunningNames)
$distributionWasRunning = $runningNames -contains $script:distro
$activeContainerIds = @()
$markerValidation = 'protected-state-and-live-registration'
if ($distributionWasRunning) {
    Assert-LiveManagedMarker
    $markerValidation = 'exact-live-root-owned-marker'
    $containerProbe = 'unset DOCKER_HOST DOCKER_CONTEXT; if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker.service; then docker --host unix:///run/docker.sock ps -q; fi'
    $activeText = Invoke-WslScriptChecked -Distribution $script:distro -ScriptText $containerProbe
    $activeContainerIds = @($activeText -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($activeContainerIds.Count -gt 0 -and -not $AcknowledgeActiveComputeContainers) {
        throw "Export found $($activeContainerIds.Count) active compute container(s). Stop them for an application-consistent backup, or explicitly pass -AcknowledgeActiveComputeContainers to accept a crash-consistent recovery snapshot."
    }
}

if (-not (Test-Path -LiteralPath $destinationParent)) { New-Item -ItemType Directory -Path $destinationParent | Out-Null }
Assert-NotReparsePoint -Path $destinationParent -Description 'export destination directory'
if ($distributionWasRunning) {
    $null = Invoke-WslScriptChecked -Distribution $script:distro -ScriptText 'sync'
    & $script:WslExe --terminate $script:distro
    if ($LASTEXITCODE -ne 0) { throw "Could not terminate $($script:distro)." }
}
& $script:WslExe --export $script:distro $Destination
if ($LASTEXITCODE -ne 0) { throw "WSL export failed (exit $LASTEXITCODE)." }

$file = Get-Item -LiteralPath $Destination
$hash = Get-FileHash -LiteralPath $Destination -Algorithm SHA256
$snapshotConsistency = if ($activeContainerIds.Count -gt 0) {
    'filesystem-crash-consistent-after-sync-active-containers-explicitly-acknowledged'
}
elseif ($distributionWasRunning) {
    'filesystem-crash-consistent-after-sync-and-terminate-no-active-containers'
}
else {
    'cold-export-of-already-stopped-distribution'
}
$manifest = [pscustomobject][ordered]@{
    generatedUtc = [DateTime]::UtcNow.ToString('o')
    distribution = $script:distro
    registrationId = $registration.registrationId
    wslVersion = $registration.version
    snapshot = $file.FullName
    bytes = $file.Length
    sha256 = $hash.Hash.ToLowerInvariant()
    distributionWasRunning = $distributionWasRunning
    activeContainerIdsAtExport = $activeContainerIds
    activeContainersAcknowledged = [bool]($activeContainerIds.Count -gt 0 -and $AcknowledgeActiveComputeContainers)
    markerValidation = $markerValidation
    snapshotConsistency = $snapshotConsistency
    purpose = 'Windows-to-Windows recovery snapshot; migrate applications to bare-metal Linux using Compose manifests and application-consistent data backups.'
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Write-Output "Export: $Destination"
Write-Output "Manifest: $manifestPath"
