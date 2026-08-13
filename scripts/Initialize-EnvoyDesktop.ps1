[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Preview', 'Enable', 'RebootProof', 'Disable')][string]$Stage,
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [string]$RustDeskExe,
    [string]$ApprovedPlanHash,
    [string]$ApprovedPlanPath,
    [switch]$AcknowledgeRustDeskConfigured,
    [switch]$AcknowledgeRustDeskTailnetWhitelist,
    [switch]$AcknowledgeRustDeskPostRebootClientTest,
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-NoReparsePathChain {
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$RequireDirectoryLeaf, [switch]$RequireFileLeaf)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root)) { throw "Path has no trusted filesystem root: $Path" }
    $current = $root
    foreach ($segment in @($fullPath.Substring($root.Length) -split '[\\/]' | Where-Object { $_ })) {
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) { throw "Required privileged path component is missing: $current" }
        if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing reparse-backed privileged path: $current" }
    }
    if ($RequireDirectoryLeaf -and -not (Test-Path -LiteralPath $fullPath -PathType Container)) { throw "Required directory does not exist: $fullPath" }
    if ($RequireFileLeaf -and -not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { throw "Required file does not exist: $fullPath" }
}

function Get-TrustedProgramFilesAuthoritySids {
    $trusted = New-Object System.Collections.Generic.HashSet[string]
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) { $null = $trusted.Add($sid) }
    try {
        $trustedInstallerSid = (New-Object Security.Principal.NTAccount('NT SERVICE\TrustedInstaller')).Translate([Security.Principal.SecurityIdentifier]).Value
        $null = $trusted.Add($trustedInstallerSid)
    }
    catch { throw 'Could not resolve the Windows Modules Installer authority used to protect Program Files.' }
    return ,$trusted
}

function Assert-NoUntrustedPathMutationAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $trustedOwners = Get-TrustedProgramFilesAuthoritySids
    $trustedRules = New-Object System.Collections.Generic.HashSet[string]
    foreach ($sid in @($trustedOwners)) { $null = $trustedRules.Add([string]$sid) }
    $null = $trustedRules.Add('S-1-3-0') # CREATOR OWNER; concrete owners are checked separately.
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    try { $ownerSid = (New-Object Security.Principal.NTAccount($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { throw "Could not resolve owner of protected RustDesk path: $Path" }
    if (-not $trustedOwners.Contains($ownerSid)) { throw "RustDesk path has an untrusted owner ($ownerSid): $Path" }
    $dangerousMask = [int](
        [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership)
    foreach ($rule in @($acl.Access)) {
        if ([string]$rule.AccessControlType -ne 'Allow') { continue }
        try { $ruleSid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
        catch { throw "Could not resolve an ACL identity on protected RustDesk path: $Path" }
        $rights = [int]$rule.FileSystemRights
        $grantsMutation = ($rights -band $dangerousMask) -ne 0 -or ($rights -band 0x10000000) -ne 0 -or ($rights -band 0x40000000) -ne 0
        if ($grantsMutation -and -not $trustedRules.Contains($ruleSid)) { throw "RustDesk path grants write/delete/ACL authority to untrusted SID $ruleSid`: $Path" }
    }
}

function Assert-RustDeskBinaryAuthority {
    param([Parameter(Mandatory = $true)][string]$Executable)
    $nativeProgramFiles = if ([string]::IsNullOrWhiteSpace($env:ProgramW6432)) { $env:ProgramFiles } else { $env:ProgramW6432 }
    $programFilesPath = [IO.Path]::GetFullPath($nativeProgramFiles)
    $rustDeskRoot = [IO.Path]::GetFullPath((Join-Path $programFilesPath 'RustDesk'))
    $fullExecutable = [IO.Path]::GetFullPath($Executable)
    if (-not $fullExecutable.StartsWith($rustDeskRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "RustDesk service executable must be installed below the native protected directory $rustDeskRoot."
    }
    Assert-NoReparsePathChain -Path $fullExecutable -RequireFileLeaf
    $resolvedExecutable = (Resolve-Path -LiteralPath $fullExecutable).Path
    if ($resolvedExecutable -ine $fullExecutable) { throw 'RustDesk executable resolution changed its canonical path.' }
    Assert-NoUntrustedPathMutationAcl -Path $programFilesPath
    $pendingPaths = New-Object 'System.Collections.Generic.Queue[string]'
    $pendingPaths.Enqueue($rustDeskRoot)
    while ($pendingPaths.Count -gt 0) {
        $path = $pendingPaths.Dequeue()
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "RustDesk installation tree contains a reparse point: $path" }
        Assert-NoUntrustedPathMutationAcl -Path $path
        if ($item.PSIsContainer) {
            foreach ($child in @(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop)) { $pendingPaths.Enqueue($child.FullName) }
        }
    }
    return $resolvedExecutable
}

function Get-RustDeskServiceAccountSid {
    param([Parameter(Mandatory = $true)][string]$StartName)
    if ($StartName -ieq 'LocalSystem' -or $StartName -ieq 'NT AUTHORITY\SYSTEM') { return 'S-1-5-18' }
    if ($StartName -ieq 'LocalService' -or $StartName -ieq 'NT AUTHORITY\LocalService' -or $StartName -ieq 'NT AUTHORITY\LOCAL SERVICE') { return 'S-1-5-19' }
    try { return (New-Object Security.Principal.NTAccount($StartName)).Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { throw "Could not resolve RustDesk service account '$StartName'." }
}

function Assert-RustDeskServiceIdentity {
    param([Parameter(Mandatory = $true)][string]$ExpectedExecutable, [switch]$RequireRunning)
    $trustedExecutable = Assert-RustDeskBinaryAuthority -Executable $ExpectedExecutable
    $services = @(Get-CimInstance Win32_Service -Filter "Name='RustDesk'" -ErrorAction Stop)
    if ($services.Count -ne 1) { throw 'Exactly one RustDesk Windows service registration is required.' }
    $service = $services[0]
    $registeredCommand = [Environment]::ExpandEnvironmentVariables(([string]$service.PathName).Trim())
    if ($registeredCommand -notmatch '^\s*"([^"]+)"\s+--service\s*$') { throw 'RustDesk service command must contain exactly the quoted installed executable and --service.' }
    $registeredExecutable = Assert-RustDeskBinaryAuthority -Executable $Matches[1]
    if ($registeredExecutable -ine $trustedExecutable) { throw 'The supplied RustDesk executable is not the exact protected executable registered for the service.' }
    $serviceAccountSid = Get-RustDeskServiceAccountSid -StartName ([string]$service.StartName)
    if ($serviceAccountSid -notin @('S-1-5-18', 'S-1-5-19')) { throw 'RustDesk service must use only the built-in LocalSystem or LocalService account.' }
    $signature = Get-AuthenticodeSignature -FilePath $trustedExecutable
    if ($signature.Status -ne 'Valid') { throw "RustDesk executable signature is not valid ($($signature.Status)). Review the official release manually." }
    $productName = (Get-Item -LiteralPath $trustedExecutable).VersionInfo.ProductName
    if ($productName -notmatch 'RustDesk') { throw "The registered service executable does not identify as RustDesk (product '$productName')." }
    if ($RequireRunning -and ([string]$service.State -ne 'Running' -or [int]$service.ProcessId -le 0)) { throw 'RustDesk service is not running with a live process.' }
    if ([string]$service.State -eq 'Running') {
        $processes = @(Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$service.ProcessId)" -ErrorAction Stop)
        if ($processes.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$processes[0].ExecutablePath) -or (Resolve-Path -LiteralPath ([string]$processes[0].ExecutablePath)).Path -ine $trustedExecutable) {
            throw 'The running RustDesk service process is not the exact protected registered executable.'
        }
    }
    return [pscustomobject]@{ Service = $service; Executable = $trustedExecutable; ServiceAccount = [string]$service.StartName; ServiceAccountSid = $serviceAccountSid; Signature = $signature }
}

function Assert-RustDeskDirectListenerIdentity {
    param([Parameter(Mandatory = $true)]$ServiceIdentity, [Parameter(Mandatory = $true)][int]$Port, [string[]]$AllowedLocalAddresses)
    $service = $ServiceIdentity.Service
    if ([string]$service.State -ne 'Running' -or [int]$service.ProcessId -le 0) { throw 'RustDesk root service is not running.' }
    $managedTcpListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { [int]$_.LocalPort -eq $Port })
    $managedUdpEndpoints = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { [int]$_.LocalPort -eq $Port })
    if ($managedTcpListeners.Count -ne 1 -or $managedUdpEndpoints.Count -ne 0) { throw 'The managed RustDesk direct port must have exactly one TCP listener and no UDP endpoint.' }
    $listener = $managedTcpListeners[0]
    if ([string]$listener.LocalAddress -notin $AllowedLocalAddresses) { throw 'The RustDesk direct listener uses an unexpected local address.' }
    $listenerProcesses = @(Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$listener.OwningProcess)" -ErrorAction Stop)
    if ($listenerProcesses.Count -ne 1) { throw 'Could not resolve exactly one RustDesk direct-listener process.' }
    $serverProcess = $listenerProcesses[0]
    if ([int]$serverProcess.ParentProcessId -ne [int]$service.ProcessId -or [string]::IsNullOrWhiteSpace([string]$serverProcess.ExecutablePath) -or
        (Resolve-Path -LiteralPath ([string]$serverProcess.ExecutablePath)).Path -ine [string]$ServiceIdentity.Executable) {
        throw 'The RustDesk direct listener is not owned by the protected child of the registered service.'
    }
    $serverCommand = [Environment]::ExpandEnvironmentVariables(([string]$serverProcess.CommandLine).Trim())
    if ($serverCommand -notmatch '^\s*"([^"]+)"\s+--server\s*$' -or (Resolve-Path -LiteralPath $Matches[1]).Path -ine [string]$ServiceIdentity.Executable) {
        throw 'The RustDesk direct-listener child command must contain exactly the protected executable and --server.'
    }
    $rustDeskProcesses = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.ExecutablePath) -and
        (Test-Path -LiteralPath ([string]$_.ExecutablePath) -PathType Leaf) -and
        (Resolve-Path -LiteralPath ([string]$_.ExecutablePath)).Path -ieq [string]$ServiceIdentity.Executable
    })
    $rustDeskProcessIds = @($rustDeskProcesses.ProcessId | ForEach-Object { [int]$_ })
    $allRustDeskTcpListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { [int]$_.OwningProcess -in $rustDeskProcessIds })
    if ($allRustDeskTcpListeners.Count -ne 1 -or [int]$allRustDeskTcpListeners[0].OwningProcess -ne [int]$serverProcess.ProcessId -or [int]$allRustDeskTcpListeners[0].LocalPort -ne $Port) {
        throw 'A RustDesk process owns an additional or unexpected TCP listener.'
    }
    return [pscustomobject]@{ ServerProcess = $serverProcess; Listener = $listener }
}

function Get-EnvoyMachineFingerprint {
    $machineGuid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$machineGuid))
        return (([BitConverter]::ToString($digest) -replace '-', '').Substring(0, 16).ToLowerInvariant())
    }
    finally { $sha.Dispose() }
}

function Get-EnvoyFirewallRule {
    param([Parameter(Mandatory = $true)][string]$Name)
    $rules = @(Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue)
    if ($rules.Count -gt 1) { throw "Multiple firewall rules use the protected name '$Name'. Review them manually." }
    if ($rules.Count -eq 1 -and $rules[0].Group -ne 'EnvoyNode') {
        throw "Firewall rule name collision: $Name is not owned by EnvoyNode."
    }
    if ($rules.Count -eq 1) { return $rules[0] }
    return $null
}

function Remove-EnvoyFirewallRules {
    param([string[]]$Names)
    foreach ($name in $Names) {
        $rule = Get-EnvoyFirewallRule -Name $name
        if ($rule) { $rule | Remove-NetFirewallRule }
    }
}

function Disable-EnvoyFirewallRules {
    param([string[]]$Names)
    foreach ($name in $Names) {
        $rule = Get-EnvoyFirewallRule -Name $name
        if ($rule) { $rule | Disable-NetFirewallRule }
    }
}

function Enable-EnvoyFirewallRules {
    param([string[]]$Names)
    foreach ($name in $Names) {
        $rule = Get-EnvoyFirewallRule -Name $name
        if ($rule) { $rule | Enable-NetFirewallRule }
    }
}

function Test-EnvoyFirewallRuleState {
    param([string[]]$Names, [string]$Direction, [string]$Action, [bool]$Enabled)
    foreach ($name in $Names) {
        $rule = Get-EnvoyFirewallRule -Name $name
        if (-not $rule -or [string]$rule.Direction -ne $Direction -or [string]$rule.Action -ne $Action -or ([string]$rule.Enabled -eq 'True') -ne $Enabled) { return $false }
    }
    return $true
}

function Assert-RustDeskAccessFailedClosed {
    param([string[]]$OwnedInboundRuleNames, [int]$Port)
    if ($Port -lt 1 -or $Port -gt 65535) { throw 'Desktop lifecycle state contains an invalid managed port.' }
    $serviceRows = @(Get-CimInstance Win32_Service -Filter "Name='RustDesk'" -ErrorAction Stop)
    if ($serviceRows.Count -gt 1) { throw 'More than one RustDesk service registration was returned.' }
    if ($serviceRows.Count -eq 1 -and ([string]$serviceRows[0].State -ne 'Stopped' -or [string]$serviceRows[0].StartMode -ne 'Disabled')) {
        throw 'RustDesk is not conclusively Stopped with Disabled startup.'
    }
    $activeStoreRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
    $enabledProtectedIngress = @($activeStoreRules | Where-Object {
        $_.Name -in $OwnedInboundRuleNames -and [string]$_.Direction -eq 'Inbound' -and [string]$_.Enabled -eq 'True'
    })
    if ($enabledProtectedIngress.Count -gt 0) { throw 'An EnvoyNode RustDesk inbound firewall rule remains enabled.' }
    $tcpListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { [int]$_.LocalPort -eq $Port })
    $udpListeners = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { [int]$_.LocalPort -eq $Port })
    if ($tcpListeners.Count -gt 0 -or $udpListeners.Count -gt 0) { throw "A TCP or UDP endpoint remains on the managed RustDesk port $Port." }
}

function Test-FirewallRecordAppliesToProgram {
    param($Record, [string]$ProgramPath, [string]$ServiceName)
    $programs = @($Record.Program | ForEach-Object { [Environment]::ExpandEnvironmentVariables([string]$_) })
    $services = @($Record.Service | ForEach-Object { [string]$_ })
    $programApplies = $programs.Count -eq 0 -or [bool]($programs | Where-Object { $_ -in @('Any', '*') -or $_ -ieq $ProgramPath })
    $serviceApplies = $services.Count -eq 0 -or [bool]($services | Where-Object { $_ -in @('Any', '*') -or $_ -ieq $ServiceName })
    return [bool]($programApplies -and $serviceApplies)
}

function Invoke-NativeText {
    param([string]$FilePath, [string[]]$ArgumentList)
    $prior = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $text = (& $FilePath @ArgumentList 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw "$FilePath failed. $text" }
        return $text
    }
    finally { $ErrorActionPreference = $prior }
}

function Get-TrustedTailscaleCommand {
    $nativeProgramFiles = if ([string]::IsNullOrWhiteSpace($env:ProgramW6432)) { $env:ProgramFiles } else { $env:ProgramW6432 }
    $commandPath = Join-Path $nativeProgramFiles 'Tailscale\tailscale.exe'
    if (-not (Test-Path -LiteralPath $commandPath)) { return $null }
    $resolvedCommand = (Resolve-Path -LiteralPath $commandPath).Path
    if ((Get-AuthenticodeSignature -FilePath $resolvedCommand).Status -ne 'Valid') { throw 'The fixed-path Tailscale CLI does not have a valid Authenticode signature.' }
    $tailscaleService = Get-CimInstance Win32_Service -Filter "Name='Tailscale'" -ErrorAction SilentlyContinue
    if (-not $tailscaleService) { throw 'The registered Tailscale Windows service is missing.' }
    $serviceCommand = [string]$tailscaleService.PathName
    if ($serviceCommand -match '^\s*"([^"]+\.exe)"') { $serviceExecutable = $Matches[1] }
    elseif ($serviceCommand -match '^\s*([^\s]+\.exe)') { $serviceExecutable = $Matches[1] }
    else { throw 'The registered Tailscale service executable path is malformed.' }
    if (-not (Test-Path -LiteralPath $serviceExecutable)) { throw 'The registered Tailscale service executable is missing.' }
    $resolvedService = (Resolve-Path -LiteralPath $serviceExecutable).Path
    $trustedDirectory = (Resolve-Path -LiteralPath (Split-Path $resolvedCommand -Parent)).Path.TrimEnd('\') + '\'
    if (-not $resolvedService.StartsWith($trustedDirectory, [StringComparison]::OrdinalIgnoreCase)) { throw 'The Tailscale service executable is outside its trusted Program Files directory.' }
    if ((Get-AuthenticodeSignature -FilePath $resolvedService).Status -ne 'Valid') { throw 'The registered Tailscale service executable does not have a valid Authenticode signature.' }
    return $resolvedCommand
}

function Assert-VerificationChecks {
    param($Verification, [string[]]$RequiredIds)
    $failed = @($Verification.checks | Where-Object { $_.id -in $RequiredIds -and $_.status -ne 'PASS' })
    $missing = @($RequiredIds | Where-Object { $_ -notin @($Verification.checks.id) })
    if ($failed.Count -gt 0 -or $missing.Count -gt 0) {
        $details = @($failed | ForEach-Object { "$($_.id): $($_.message)" }) + @($missing | ForEach-Object { "$_`: missing" })
        throw 'Required live safety checks failed: ' + ($details -join '; ')
    }
}

function Protect-EnvoyStateDirectory {
    param([string]$Path, [switch]$AllowRepairWithContent)
    $privilegedRoot = Split-Path $Path -Parent
    foreach ($candidate in @($privilegedRoot, $Path)) {
        if (Test-Path -LiteralPath $candidate) {
            $item = Get-Item -LiteralPath $candidate -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Privileged state path is a reparse point: $candidate" }
        }
    }
    $hadContent = [bool](Test-Path -LiteralPath $Path) -and @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue).Count -gt 0
    if ($hadContent -and -not $AllowRepairWithContent -and -not (Test-ExactPrivilegedDirectoryAcl -Path $Path)) { throw 'Privileged state contains data under a non-exact ACL. Refusing to adopt or repair potentially forged lifecycle state.' }
    foreach ($directory in @($privilegedRoot, $Path)) {
        if (-not (Test-Path -LiteralPath $directory)) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
        $item = Get-Item -LiteralPath $directory -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Privileged state path became a reparse point: $directory" }
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $administrators = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
        $acl.SetOwner($administrators)
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        $propagation = [Security.AccessControl.PropagationFlags]::None
        $allow = [Security.AccessControl.AccessControlType]::Allow
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, $propagation, $allow)))
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($administrators, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, $propagation, $allow)))
        Set-Acl -LiteralPath $directory -AclObject $acl
        if (-not (Test-ExactPrivilegedDirectoryAcl -Path $directory)) { throw "Could not establish the exact privileged ACL on $directory" }
    }
}

function Test-ExactPrivilegedDirectoryAcl {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $false }
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        $acl = Get-Acl -LiteralPath $Path
        if (-not $acl.AreAccessRulesProtected) { return $false }
        try { $ownerSid = (New-Object Security.Principal.NTAccount($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { return $false }
        if ($ownerSid -ne 'S-1-5-32-544') { return $false }
        $allowed = @('S-1-5-18', 'S-1-5-32-544')
        if (@($acl.Access).Count -ne 2) { return $false }
        $seen = New-Object System.Collections.Generic.HashSet[string]
        $expectedInheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        foreach ($rule in @($acl.Access)) {
            try { $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { return $false }
            if ($rule.IsInherited -or $sid -notin $allowed -or [string]$rule.AccessControlType -ne 'Allow' -or [int]$rule.FileSystemRights -ne [int][Security.AccessControl.FileSystemRights]::FullControl -or $rule.InheritanceFlags -ne $expectedInheritance -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { return $false }
            $null = $seen.Add($sid)
        }
        return [bool]($seen.Count -eq 2 -and @($allowed | Where-Object { -not $seen.Contains($_) }).Count -eq 0)
    }
    catch { return $false }
}

function Test-ExactPrivilegedFileAcl {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        $acl = Get-Acl -LiteralPath $Path
        if (-not $acl.AreAccessRulesProtected) { return $false }
        try { $ownerSid = (New-Object Security.Principal.NTAccount($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { return $false }
        if ($ownerSid -ne 'S-1-5-32-544') { return $false }
        $allowed = @('S-1-5-18', 'S-1-5-32-544')
        if (@($acl.Access).Count -ne 2) { return $false }
        $seen = New-Object System.Collections.Generic.HashSet[string]
        foreach ($rule in @($acl.Access)) {
            try { $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { return $false }
            if ($rule.IsInherited -or $sid -notin $allowed -or [string]$rule.AccessControlType -ne 'Allow' -or [int]$rule.FileSystemRights -ne [int][Security.AccessControl.FileSystemRights]::FullControl -or $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { return $false }
            $null = $seen.Add($sid)
        }
        return [bool]($seen.Count -eq 2 -and @($allowed | Where-Object { -not $seen.Contains($_) }).Count -eq 0)
    }
    catch { return $false }
}

function Test-SafeEnvoyStateJournalTarget {
    param([Parameter(Mandatory = $true)][string]$DirectoryPath, [Parameter(Mandatory = $true)][string]$FilePath)
    try {
        $fullDirectory = [IO.Path]::GetFullPath($DirectoryPath)
        $fullFile = [IO.Path]::GetFullPath($FilePath)
        if ([IO.Path]::GetFullPath((Split-Path $fullFile -Parent)) -ine $fullDirectory) { return $false }
        $privilegedRoot = Split-Path $fullDirectory -Parent
        Assert-NoReparsePathChain -Path $privilegedRoot -RequireDirectoryLeaf
        Assert-NoReparsePathChain -Path $fullDirectory -RequireDirectoryLeaf
        if (-not (Test-ExactPrivilegedDirectoryAcl -Path $privilegedRoot) -or -not (Test-ExactPrivilegedDirectoryAcl -Path $fullDirectory)) { return $false }
        if (Test-Path -LiteralPath $fullFile) {
            Assert-NoReparsePathChain -Path $fullFile -RequireFileLeaf
            return (Test-ExactPrivilegedFileAcl -Path $fullFile)
        }
        return $true
    }
    catch { return $false }
}

function Protect-EnvoyStateFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Privileged state file is missing: $Path" }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Privileged state file is a reparse point: $Path" }
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $administrators = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl.SetOwner($administrators)
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $none = [Security.AccessControl.InheritanceFlags]::None
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system, [Security.AccessControl.FileSystemRights]::FullControl, $none, $propagation, $allow)))
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($administrators, [Security.AccessControl.FileSystemRights]::FullControl, $none, $propagation, $allow)))
    Set-Acl -LiteralPath $Path -AclObject $acl
    if (-not (Test-ExactPrivilegedFileAcl -Path $Path)) { throw "Could not establish the exact privileged file ACL on $Path" }
}

function Write-EnvoyStateFile {
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Path, [int]$Depth = 6)
    $directory = Split-Path $Path -Parent
    $temporaryPath = Join-Path $directory ('.state-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllText($temporaryPath, ($Value | ConvertTo-Json -Depth $Depth), (New-Object Text.UTF8Encoding($false)))
        Protect-EnvoyStateFile -Path $temporaryPath
        Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
        Protect-EnvoyStateFile -Path $Path
    }
    finally { Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue }
}

$inboundRuleNames = @('EnvoyNode-RustDesk-Tailnet-IPv4', 'EnvoyNode-RustDesk-Tailnet-IPv6')
$outboundRuleNames = @('EnvoyNode-RustDesk-Block-Public-IPv4', 'EnvoyNode-RustDesk-Block-Public-IPv6')
$ruleNames = @($inboundRuleNames + $outboundRuleNames)
$stateDir = Join-Path $env:ProgramData 'EnvoyNode\state'
$desktopStatePath = Join-Path $stateDir 'desktop-current.json'
$machineFingerprint = Get-EnvoyMachineFingerprint

# Disable is an emergency, machine-state-driven path. It intentionally does not
# depend on a surviving project config or executable-discovery setting.
if ($Stage -eq 'Disable') {
    if (-not $Apply) { throw 'Disable requires -Apply.' }
    if ($WhatIfPreference) { Write-Output 'Would stop and startup-disable managed RustDesk, disable managed ingress, and preserve existing managed egress blocks.'; return }
    if (-not (Test-IsElevated)) { throw 'Disable must run in an elevated PowerShell window.' }
    Protect-EnvoyStateDirectory -Path $stateDir -AllowRepairWithContent
    if (-not (Test-ExactPrivilegedFileAcl -Path $desktopStatePath)) { throw 'No exactly protected EnvoyNode desktop state exists; refusing to stop an unmanaged RustDesk service.' }
    $priorDesktopState = Get-Content -LiteralPath $desktopStatePath -Raw | ConvertFrom-Json
    $priorStateProperties = @($priorDesktopState.PSObject.Properties.Name)
    if ($priorDesktopState.schemaVersion -ne 1 -or $priorDesktopState.machineFingerprint -ne $machineFingerprint -or 'port' -notin $priorStateProperties -or [int]$priorDesktopState.port -lt 1 -or [int]$priorDesktopState.port -gt 65535) { throw 'Desktop state is not exactly bound to this Windows installation and a valid managed port.' }
    $managedPort = [int]$priorDesktopState.port
    $service = Get-Service RustDesk -ErrorAction SilentlyContinue
    $disableErrors = New-Object System.Collections.Generic.List[string]
    try { Disable-EnvoyFirewallRules -Names $inboundRuleNames } catch { $disableErrors.Add("managed ingress: $($_.Exception.Message)") }
    try { Enable-EnvoyFirewallRules -Names $outboundRuleNames } catch { $disableErrors.Add("public-egress blocks: $($_.Exception.Message)") }
    if ($service) {
        try { Set-Service -Name $service.Name -StartupType Disabled -ErrorAction Stop } catch { $disableErrors.Add("service startup: $($_.Exception.Message)") }
        try {
            Stop-Service -Name $service.Name -Force -ErrorAction Stop
            (Get-Service -Name $service.Name -ErrorAction Stop).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
        } catch { $disableErrors.Add("service stop: $($_.Exception.Message)") }
    }
    $failCloseError = $null
    try { Assert-RustDeskAccessFailedClosed -OwnedInboundRuleNames $inboundRuleNames -Port $managedPort }
    catch { $failCloseError = $_.Exception.Message }
    $egressBlocksReady = $false
    try { $egressBlocksReady = Test-EnvoyFirewallRuleState -Names $outboundRuleNames -Direction 'Outbound' -Action 'Block' -Enabled $true } catch { }
    $disabledState = [pscustomobject][ordered]@{ schemaVersion = 1; machineFingerprint = $machineFingerprint; generatedUtc = [DateTime]::UtcNow.ToString('o'); status = if ([string]::IsNullOrWhiteSpace($failCloseError)) { 'disabled-break-glass' } else { 'disable-incomplete-fail-close-unproven' }; port = $managedPort; serviceStartup = 'Disabled'; publicEgressBlocksPreserved = $egressBlocksReady }
    Write-EnvoyStateFile -Value $disabledState -Path $desktopStatePath -Depth 5
    if (-not [string]::IsNullOrWhiteSpace($failCloseError)) { throw "Desktop shutdown attempted every independent closure path, but fail-close could not be proven. Use the local console immediately. $failCloseError Attempts: $($disableErrors -join '; ')" }
    $egressMessage = if ($egressBlocksReady) { 'Existing public-egress block rules remain enabled as a fail-safe.' } else { 'Managed public-egress block rules were not all present and enabled; inbound desktop access is still proven closed, but review the egress rules locally.' }
    Write-Output "EnvoyNode RustDesk is proven stopped/startup-disabled with protected ingress off and no managed-port endpoint. $egressMessage"
    return
}

if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Configuration file not found: $ConfigPath" }
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$desktop = $config.access.desktop
if ($desktop.provider -ne 'rustdesk-direct') { throw 'This Windows Home adapter supports rustdesk-direct only.' }
$port = [int]$desktop.port
if ($port -lt 1 -or $port -gt 65535) { throw 'Invalid RustDesk direct port.' }

$nativeProgramFiles = if ([string]::IsNullOrWhiteSpace($env:ProgramW6432)) { $env:ProgramFiles } else { $env:ProgramW6432 }
$plannedRustDeskExe = [IO.Path]::GetFullPath((Join-Path $nativeProgramFiles 'RustDesk\rustdesk.exe'))
if ([string]::IsNullOrWhiteSpace($RustDeskExe)) { $RustDeskExe = $plannedRustDeskExe }
$exePresent = [bool]($RustDeskExe -and (Test-Path -LiteralPath $RustDeskExe))
$service = Get-Service RustDesk -ErrorAction SilentlyContinue
$listener = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
$projectRoot = Split-Path $PSScriptRoot -Parent

$preview = [pscustomobject][ordered]@{
    stage = $Stage
    configEnabled = [bool]$desktop.enabled
    provider = $desktop.provider
    port = $port
    executable = $RustDeskExe
    executablePresent = $exePresent
    serviceStatus = if ($service) { [string]$service.Status } else { $null }
    listenerCount = $listener.Count
    interactiveGates = @(
        'Install a stable RustDesk release from the official project.',
        'Set a unique permanent password in the GUI; never pass it on a command line.',
        'Enable direct IP access.',
        'Enable IP Whitelisting for 100.64.0.0/10 and fd7a:115c:a1e0::/48 (or exact client tailnet IPs).',
        'Disable LAN discovery and remote configuration; disable every unused permission.',
        'Leave RustDesk proxy, ID server, relay server, and API server fields empty.',
        "Add TCP $port to the reviewed Tailscale policy.",
        'Prove SSH recovery first.'
    )
}
if ($Stage -eq 'Preview') { $preview | ConvertTo-Json -Depth 6; return }
if (-not $Apply) { throw "$Stage requires -Apply." }
if ($WhatIfPreference) { $preview | ConvertTo-Json -Depth 6; return }
if (-not (Test-IsElevated)) { throw "$Stage must run in an elevated PowerShell window." }
if ([IO.Path]::GetFullPath($RustDeskExe) -ine $plannedRustDeskExe) { throw 'Desktop mutation requires the default protected Program Files\RustDesk\rustdesk.exe path bound into the reviewed plan.' }
& (Join-Path $PSScriptRoot 'Assert-EnvoyPlanApproval.ps1') -Action ("Desktop" + $Stage) -ConfigPath $ConfigPath -ApprovedPlanHash $ApprovedPlanHash -ApprovedPlanPath $ApprovedPlanPath

# Scope and identity checks precede every Enable mutation. In particular, a
# reviewed plan with desktop disabled must never stop an existing service.
if ($Stage -eq 'Enable') {
    if (-not $desktop.enabled) { throw 'access.desktop.enabled is false. Opt in through the local config first.' }
    if ($desktop.requireTailnetWhitelist -ne $true -or $desktop.blockPublicRustDeskEgress -ne $true -or $desktop.disableLanDiscovery -ne $true -or $desktop.disableRemoteConfiguration -ne $true) {
        throw 'The desktop config must require a tailnet whitelist, public RustDesk egress blocks, disabled LAN discovery, and disabled remote configuration.'
    }
    if (-not $AcknowledgeRustDeskConfigured) { throw 'Pass -AcknowledgeRustDeskConfigured only after completing and reviewing every interactive RustDesk security setting.' }
    if (-not $AcknowledgeRustDeskTailnetWhitelist) { throw 'Pass -AcknowledgeRustDeskTailnetWhitelist only after IP Whitelisting is limited to the Tailscale ranges or exact approved client tailnet IPs.' }
    if (-not $exePresent) { throw 'RustDesk executable not found. Supply -RustDeskExe with the installed executable path.' }
    if (-not $service) { throw 'RustDesk is not installed as a Windows service; unattended desktop recovery would be unreliable.' }

    $rustDeskIdentity = Assert-RustDeskServiceIdentity -ExpectedExecutable $RustDeskExe
    $serviceCim = $rustDeskIdentity.Service
    $signature = $rustDeskIdentity.Signature
    $RustDeskExe = $rustDeskIdentity.Executable
}

if ($Stage -eq 'RebootProof' -and (-not $desktop.enabled -or $desktop.requireTailnetWhitelist -ne $true -or $desktop.blockPublicRustDeskEgress -ne $true -or $desktop.disableLanDiscovery -ne $true -or $desktop.disableRemoteConfiguration -ne $true -or -not $AcknowledgeRustDeskTailnetWhitelist -or -not $AcknowledgeRustDeskPostRebootClientTest)) {
    throw 'RebootProof requires the full private desktop configuration, a renewed tailnet-whitelist acknowledgement, and explicit acknowledgement of a successful second-laptop GUI test after this reboot.'
}

if ($Stage -ne 'RebootProof') { Protect-EnvoyStateDirectory -Path $stateDir }
$requiredAccessChecks = @('no-public-ports-config', 'tailnet-policy-config', 'plan-review-policy', 'managed-device-policy', 'desktop-security-config', 'no-windows-portproxy', 'managed-port-firewall-scope', 'windows-firewall-profiles', 'tailscale-online', 'tailscale-forwarding-empty', 'tailscale-node-key-expiry', 'tailscale-adapter-binding', 'sshd-running', 'sshd-service-identity', 'ssh-key-only', 'ssh-key-allowlist', 'access-state-integrity', 'ssh-current-boot-proof', 'ssh-listener-ownership', 'ssh-tailnet-firewall', 'global-managed-port-exposure', 'defender', 'uac', 'secure-boot', 'pending-reboot-clear', 'drive-encryption')

if ($Stage -eq 'RebootProof') {
    $rebootClosurePorts = New-Object 'System.Collections.Generic.HashSet[int]'
    $null = $rebootClosurePorts.Add($port)
    try {
        Protect-EnvoyStateDirectory -Path $stateDir
        if (-not (Test-ExactPrivilegedFileAcl -Path $desktopStatePath)) { throw 'Exactly protected desktop activation state is missing.' }
        $priorState = Get-Content -LiteralPath $desktopStatePath -Raw | ConvertFrom-Json
        $priorStateProperties = @($priorState.PSObject.Properties.Name)
        if (@('port', 'executable', 'executableSha256', 'serviceAccount', 'serviceAccountSid', 'serviceCommandMode', 'serverCommandMode') | Where-Object { $_ -notin $priorStateProperties }) { throw 'DesktopRebootProof state lacks protected service identity fields.' }
        $priorManagedPort = [int]$priorState.port
        if ($priorManagedPort -ge 1 -and $priorManagedPort -le 65535) { $null = $rebootClosurePorts.Add($priorManagedPort) }
        if ($priorState.schemaVersion -ne 1 -or $priorState.machineFingerprint -ne $machineFingerprint -or $priorState.status -notin @('enabled-awaiting-reboot-proof', 'enabled-tailnet-only') -or [int]$priorState.port -ne $port -or [string]$priorState.serviceCommandMode -cne '--service' -or [string]$priorState.serverCommandMode -cne '--server') { throw 'DesktopRebootProof requires machine-bound enabled state on the reviewed managed port and service commands.' }
        $rebootIdentity = Assert-RustDeskServiceIdentity -ExpectedExecutable ([string]$priorState.executable) -RequireRunning
        if ([string]$rebootIdentity.ServiceAccountSid -cne [string]$priorState.serviceAccountSid -or [string]$rebootIdentity.ServiceAccount -ine [string]$priorState.serviceAccount -or
            (Get-FileHash -LiteralPath $rebootIdentity.Executable -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$priorState.executableSha256) {
            throw 'RustDesk protected binary, hash, or built-in service account drifted before reboot proof.'
        }
        $currentBoot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime()
        $enabledBoot = [DateTime]::Parse([string]$priorState.enabledBootUtc).ToUniversalTime()
        $referenceBoot = $enabledBoot
        if ($priorState.status -eq 'enabled-tailnet-only') {
            if ($priorState.PSObject.Properties.Name -notcontains 'desktopProofBootUtc') { throw 'Previously proven desktop state lacks its proof boot timestamp.' }
            $referenceBoot = [DateTime]::Parse([string]$priorState.desktopProofBootUtc).ToUniversalTime()
        }
        if ($currentBoot -le $referenceBoot) { throw 'No later Windows boot exists to renew the desktop proof. Reboot with local/SSH recovery available, test the GUI path from the second laptop, then accept the proof.' }
        $priorState.status = 'enabled-tailnet-only'
        if ($priorState.PSObject.Properties.Name -contains 'desktopProofBootUtc') { $priorState.desktopProofBootUtc = $currentBoot.ToString('o') } else { $priorState | Add-Member -NotePropertyName desktopProofBootUtc -NotePropertyValue $currentBoot.ToString('o') }
        if ($priorState.PSObject.Properties.Name -contains 'desktopProofAcceptedUtc') { $priorState.desktopProofAcceptedUtc = [DateTime]::UtcNow.ToString('o') } else { $priorState | Add-Member -NotePropertyName desktopProofAcceptedUtc -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) }
        if ($priorState.PSObject.Properties.Name -contains 'postRebootClientTestAcknowledged') { $priorState.postRebootClientTestAcknowledged = $true } else { $priorState | Add-Member -NotePropertyName postRebootClientTestAcknowledged -NotePropertyValue $true }
        Write-EnvoyStateFile -Value $priorState -Path $desktopStatePath -Depth 6
        $proofVerification = & (Join-Path $PSScriptRoot 'Test-EnvoyNode.ps1') -ConfigPath $ConfigPath -PassThru -NoReport
        Assert-VerificationChecks -Verification $proofVerification -RequiredIds @($requiredAccessChecks + @('desktop-state-integrity', 'desktop-firewall-conflicts', 'desktop-tailnet-only'))
    }
    catch {
        $proofError = $_
        try { Disable-EnvoyFirewallRules -Names $inboundRuleNames } catch { }
        try { Enable-EnvoyFirewallRules -Names $outboundRuleNames } catch { }
        Set-Service RustDesk -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service RustDesk -Force -ErrorAction SilentlyContinue
        $proofFailCloseErrors = New-Object System.Collections.Generic.List[string]
        foreach ($closurePort in @($rebootClosurePorts | Sort-Object)) {
            try { Assert-RustDeskAccessFailedClosed -OwnedInboundRuleNames $inboundRuleNames -Port ([int]$closurePort) }
            catch { $proofFailCloseErrors.Add("port $closurePort`: $($_.Exception.Message)") }
        }
        $proofFailCloseError = $proofFailCloseErrors -join '; '
        $proofInboundClosed = $false
        $proofEgressReady = $false
        try { $proofInboundClosed = Test-EnvoyFirewallRuleState -Names @($inboundRuleNames | Where-Object { Get-EnvoyFirewallRule -Name $_ }) -Direction 'Inbound' -Action 'Allow' -Enabled $false } catch { }
        try { $proofEgressReady = Test-EnvoyFirewallRuleState -Names $outboundRuleNames -Direction 'Outbound' -Action 'Block' -Enabled $true } catch { }
        $failedProofState = [pscustomobject][ordered]@{ schemaVersion = 1; machineFingerprint = $machineFingerprint; generatedUtc = [DateTime]::UtcNow.ToString('o'); status = if ([string]::IsNullOrWhiteSpace($proofFailCloseError)) { 'reboot-proof-failed-closed' } else { 'reboot-proof-failed-needs-local-console' }; port = $port; closurePorts = @($rebootClosurePorts | Sort-Object); serviceStartup = 'Disabled'; failCloseProven = [string]::IsNullOrWhiteSpace($proofFailCloseError); inboundDisabled = $proofInboundClosed; publicEgressBlocksPreserved = $proofEgressReady; error = $proofError.Exception.Message }
        $proofJournalError = $null
        if (Test-SafeEnvoyStateJournalTarget -DirectoryPath $stateDir -FilePath $desktopStatePath) {
            try { Write-EnvoyStateFile -Value $failedProofState -Path $desktopStatePath -Depth 6 }
            catch { $proofJournalError = "State journal write failed after closure: $($_.Exception.Message)" }
        }
        else { $proofJournalError = 'State journal unavailable/unsafe; no elevated failure-journal write was attempted.' }
        if ([string]::IsNullOrWhiteSpace($proofFailCloseError) -and [string]::IsNullOrWhiteSpace($proofJournalError)) { throw "Desktop reboot verification failed closed: $($proofError.Exception.Message)" }
        $closureDetail = if ([string]::IsNullOrWhiteSpace($proofFailCloseError)) { 'Access was proven closed.' } else { "Fail-close: $proofFailCloseError" }
        $journalDetail = if ([string]::IsNullOrWhiteSpace($proofJournalError)) { '' } else { " $proofJournalError" }
        throw "Desktop reboot verification failed and requires immediate local-console investigation: $($proofError.Exception.Message) $closureDetail$journalDetail"
    }
    Write-Output 'RustDesk tailnet-only service, listener, firewall, signer, and current-boot recovery were verified after a later reboot.'
    return
}

# Any approved Enable attempt first closes the stock service path. If a later
# validation fails, RustDesk stays stopped and startup-disabled.
try {
    if (-not (Test-Path -LiteralPath $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
    $stoppingState = [pscustomobject][ordered]@{ schemaVersion = 1; machineFingerprint = $machineFingerprint; generatedUtc = [DateTime]::UtcNow.ToString('o'); status = 'enable-stop-in-progress'; port = $port; serviceStartup = 'disabling' }
    Write-EnvoyStateFile -Value $stoppingState -Path $desktopStatePath -Depth 5
    Set-Service -Name $service.Name -StartupType Disabled -ErrorAction Stop
    Stop-Service -Name $service.Name -Force -ErrorAction Stop
    (Get-Service -Name $service.Name -ErrorAction Stop).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
    Assert-RustDeskAccessFailedClosed -OwnedInboundRuleNames $inboundRuleNames -Port $port
    $validatingState = [pscustomobject][ordered]@{ schemaVersion = 1; machineFingerprint = $machineFingerprint; generatedUtc = [DateTime]::UtcNow.ToString('o'); status = 'enable-validation-in-progress'; port = $port; serviceStartup = 'Disabled' }
    Write-EnvoyStateFile -Value $validatingState -Path $desktopStatePath -Depth 5

    $accessStatePath = Join-Path $stateDir 'access-current.json'
    if (-not (Test-Path -LiteralPath $accessStatePath)) { throw 'A managed SSH recovery state is required before enabling unattended desktop control.' }
    $accessState = Get-Content -LiteralPath $accessStatePath -Raw | ConvertFrom-Json
    if ($accessState.machineFingerprint -ne $machineFingerprint -or $accessState.status -ne 'hardened-key-only') { throw 'Prove and harden machine-bound key-only SSH recovery before enabling unattended desktop control.' }
    $accessProperties = @($accessState.PSObject.Properties.Name)
    if ('rebootProofBootUtc' -notin $accessProperties) { throw 'Accept a fresh second-device SSH proof after reboot before enabling unattended desktop control.' }
    $currentBoot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime()
    $provedBoot = [DateTime]::Parse($accessState.rebootProofBootUtc).ToUniversalTime()
    if ([math]::Abs(($currentBoot - $provedBoot).TotalSeconds) -ge 2) { throw 'The current Windows boot has not passed the fresh second-device SSH recovery proof.' }

    $accessVerification = & (Join-Path $PSScriptRoot 'Test-EnvoyNode.ps1') -ConfigPath $ConfigPath -PassThru -NoReport
    Assert-VerificationChecks -Verification $accessVerification -RequiredIds $requiredAccessChecks

    $tailscalePath = Get-TrustedTailscaleCommand
    if (-not $tailscalePath) { throw 'Tailscale is not installed.' }
    $status = (Invoke-NativeText -FilePath $tailscalePath -ArgumentList @('status', '--json')) | ConvertFrom-Json
    if ($status.BackendState -ne 'Running' -or -not $status.Self.Online) { throw 'Tailscale is not online.' }
    $ipv4 = (Invoke-NativeText -FilePath $tailscalePath -ArgumentList @('ip', '-4')).Trim()
    $ipv6 = $null
    try { $ipv6 = (Invoke-NativeText -FilePath $tailscalePath -ArgumentList @('ip', '-6')).Trim() } catch { }
    $ipObject = Get-NetIPAddress -IPAddress $ipv4 -ErrorAction Stop
    $adapters = @(Get-NetAdapter -InterfaceIndex $ipObject.InterfaceIndex -ErrorAction Stop)
    if ($adapters.Count -ne 1) { throw 'Could not resolve exactly one Tailscale adapter.' }

    $audit = & (Join-Path $PSScriptRoot 'Get-EnvoyAudit.ps1') -AdditionalSensitivePorts @($port) -PassThru -NoReport
    if (-not $audit.access.firewallInspectionComplete) { throw 'The elevated firewall inspection was incomplete. RustDesk remains stopped and startup-disabled.' }
    if (-not $audit.access.firewallProfilesSecure) { throw 'All Windows Firewall profiles must be enabled with default inbound blocking. RustDesk remains disabled.' }
    if (-not $audit.access.portProxyInspectionComplete -or $audit.access.localPortProxyConfigured) { throw 'Windows port-proxy inspection is incomplete or a forwarding rule exists. RustDesk remains stopped and startup-disabled.' }
    $outboundAllowBypassRules = @($audit.access.outboundAllowBypassRules)
    if (-not $audit.access.outboundAllowBypassInspectionComplete -or $outboundAllowBypassRules.Count -gt 0) { throw 'An outbound authenticated allow-bypass rule exists or could not be inspected. It could override RustDesk public-egress blocks, so RustDesk remains disabled.' }
    $unexpectedOutboundBlocks = @($audit.access.outboundBlockRules | Where-Object {
        $_.Name -notin $outboundRuleNames -and
        (Test-FirewallRecordAppliesToProgram -Record $_ -ProgramPath $RustDeskExe -ServiceName 'RustDesk')
    })
    if (-not $audit.access.outboundBlockInspectionComplete -or $unexpectedOutboundBlocks.Count -gt 0) { throw 'An unrelated outbound block can apply to RustDesk or outbound block inspection was incomplete. Review it before activation so the private direct path remains provably reachable.' }
    $unexpectedRules = @($audit.access.sensitiveFirewallRules | Where-Object {
        $_.Port -eq $port -and $_.Enabled -eq 'True' -and $_.Action -in @('Allow', 'Block') -and
        $_.Name -notin $ruleNames -and
        (Test-FirewallRecordAppliesToProgram -Record $_ -ProgramPath $RustDeskExe -ServiceName 'RustDesk')
    })
    if ($unexpectedRules.Count -gt 0) { throw 'A non-EnvoyNode RustDesk allow/block rule can apply to this service. Review it manually; RustDesk remains disabled.' }

    foreach ($name in $ruleNames) {
        $null = Get-EnvoyFirewallRule -Name $name
    }
    Remove-EnvoyFirewallRules -Names $ruleNames
    # Explicit block rules prevent RustDesk's default public rendezvous/relay path
    # while leaving loopback and the Tailscale address ranges reachable.
    New-NetFirewallRule -Name $outboundRuleNames[0] -DisplayName 'EnvoyNode block RustDesk public IPv4 egress' -Group 'EnvoyNode' -Direction Outbound -Action Block -Protocol Any -RemoteAddress @('0.0.0.0-100.63.255.255', '100.128.0.0-126.255.255.255', '128.0.0.0-255.255.255.255') -Profile Any -Program $RustDeskExe | Out-Null
    New-NetFirewallRule -Name $outboundRuleNames[1] -DisplayName 'EnvoyNode block RustDesk public IPv6 egress' -Group 'EnvoyNode' -Direction Outbound -Action Block -Protocol Any -RemoteAddress @('::2-fd7a:115c:a1df:ffff:ffff:ffff:ffff:ffff', 'fd7a:115c:a1e1::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') -Profile Any -Program $RustDeskExe | Out-Null
    New-NetFirewallRule -Name $inboundRuleNames[0] -DisplayName 'EnvoyNode RustDesk via Tailscale IPv4' -Group 'EnvoyNode' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -LocalAddress $ipv4 -RemoteAddress '100.64.0.0/10' -InterfaceAlias $adapters[0].Name -Profile Any -Program $RustDeskExe | Out-Null
    if ($ipv6) {
        New-NetFirewallRule -Name $inboundRuleNames[1] -DisplayName 'EnvoyNode RustDesk via Tailscale IPv6' -Group 'EnvoyNode' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -LocalAddress $ipv6 -RemoteAddress 'fd7a:115c:a1e0::/48' -InterfaceAlias $adapters[0].Name -Profile Any -Program $RustDeskExe | Out-Null
    }
    $provisionalState = [pscustomobject][ordered]@{
        schemaVersion = 1; machineFingerprint = $machineFingerprint; generatedUtc = [DateTime]::UtcNow.ToString('o'); status = 'enable-in-progress'
        executable = (Resolve-Path -LiteralPath $RustDeskExe).Path; executableSha256 = (Get-FileHash -LiteralPath $RustDeskExe -Algorithm SHA256).Hash.ToLowerInvariant(); signer = $signature.SignerCertificate.Subject
        serviceAccount = $rustDeskIdentity.ServiceAccount; serviceAccountSid = $rustDeskIdentity.ServiceAccountSid; serviceCommandMode = '--service'; serverCommandMode = '--server'
        port = $port; tailscaleIPv4 = $ipv4; tailscaleIPv6 = $ipv6; tailscaleAdapter = $adapters[0].Name
        whitelistAcknowledged = $true; publicEgressBlocked = $true
    }
    Write-EnvoyStateFile -Value $provisionalState -Path $desktopStatePath -Depth 6
    $preStartDesktopVerification = & (Join-Path $PSScriptRoot 'Test-EnvoyNode.ps1') -ConfigPath $ConfigPath -PassThru -NoReport
    Assert-VerificationChecks -Verification $preStartDesktopVerification -RequiredIds @('no-windows-portproxy', 'managed-port-firewall-scope', 'windows-firewall-profiles', 'desktop-state-integrity', 'desktop-firewall-conflicts', 'desktop-firewall-exact', 'global-managed-port-exposure')
    Set-Service -Name $service.Name -StartupType Manual
    Start-Service -Name $service.Name
    Start-Sleep -Seconds 2
    $runningIdentity = Assert-RustDeskServiceIdentity -ExpectedExecutable $RustDeskExe -RequireRunning
    if ([string]$runningIdentity.ServiceAccountSid -cne [string]$rustDeskIdentity.ServiceAccountSid -or [string]$runningIdentity.ServiceAccount -ine [string]$rustDeskIdentity.ServiceAccount) { throw 'RustDesk built-in service account changed during activation.' }
    $allowedListenerAddresses = @('0.0.0.0', '::', $ipv4)
    if ($ipv6) { $allowedListenerAddresses += $ipv6 }
    $listenerIdentity = Assert-RustDeskDirectListenerIdentity -ServiceIdentity $runningIdentity -Port $port -AllowedLocalAddresses $allowedListenerAddresses
    if (-not (Test-Path -LiteralPath $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
    $enabledState = [pscustomobject][ordered]@{
        schemaVersion = 1
        machineFingerprint = $machineFingerprint
        generatedUtc = [DateTime]::UtcNow.ToString('o')
        status = 'enabled-awaiting-reboot-proof'
        enabledUtc = [DateTime]::UtcNow.ToString('o')
        enabledBootUtc = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('o')
        executable = (Resolve-Path -LiteralPath $RustDeskExe).Path
        executableSha256 = (Get-FileHash -LiteralPath $RustDeskExe -Algorithm SHA256).Hash.ToLowerInvariant()
        signer = $signature.SignerCertificate.Subject
        serviceAccount = $rustDeskIdentity.ServiceAccount
        serviceAccountSid = $rustDeskIdentity.ServiceAccountSid
        serviceCommandMode = '--service'
        serverCommandMode = '--server'
        port = $port
        tailscaleIPv4 = $ipv4
        tailscaleIPv6 = $ipv6
        tailscaleAdapter = $adapters[0].Name
        serviceProcessIdAtEnable = [int]$runningIdentity.Service.ProcessId
        serverProcessIdAtEnable = [int]$listenerIdentity.ServerProcess.ProcessId
        whitelistAcknowledged = $true
        publicEgressBlocked = $true
    }
    Write-EnvoyStateFile -Value $enabledState -Path $desktopStatePath -Depth 6
    Set-Service -Name $service.Name -StartupType Automatic
    $desktopVerification = & (Join-Path $PSScriptRoot 'Test-EnvoyNode.ps1') -ConfigPath $ConfigPath -PassThru -NoReport
    Assert-VerificationChecks -Verification $desktopVerification -RequiredIds @($requiredAccessChecks + @('desktop-state-integrity', 'desktop-firewall-conflicts', 'desktop-firewall-exact', 'desktop-live-posture'))
}
catch {
    $activationError = $_
    try { Set-Service -Name $service.Name -StartupType Disabled -ErrorAction SilentlyContinue } catch { }
    try { Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue } catch { }
    try { Disable-EnvoyFirewallRules -Names $inboundRuleNames } catch { }
    try { Enable-EnvoyFirewallRules -Names $outboundRuleNames } catch { }
    $activationFailCloseError = $null
    try { Assert-RustDeskAccessFailedClosed -OwnedInboundRuleNames $inboundRuleNames -Port $port }
    catch { $activationFailCloseError = $_.Exception.Message }
    $inboundDisabled = $false
    $egressBlocksReady = $false
    try { $inboundDisabled = Test-EnvoyFirewallRuleState -Names @($inboundRuleNames | Where-Object { Get-EnvoyFirewallRule -Name $_ }) -Direction 'Inbound' -Action 'Allow' -Enabled $false } catch { }
    try { $egressBlocksReady = Test-EnvoyFirewallRuleState -Names $outboundRuleNames -Direction 'Outbound' -Action 'Block' -Enabled $true } catch { }
    $failedState = [pscustomobject][ordered]@{ schemaVersion = 1; machineFingerprint = $machineFingerprint; generatedUtc = [DateTime]::UtcNow.ToString('o'); status = if ([string]::IsNullOrWhiteSpace($activationFailCloseError)) { 'activation-failed-closed' } else { 'activation-failed-needs-local-console' }; port = $port; serviceStartup = 'Disabled'; failCloseProven = [string]::IsNullOrWhiteSpace($activationFailCloseError); inboundDisabled = $inboundDisabled; publicEgressBlocksPreserved = $egressBlocksReady; error = $activationError.Exception.Message }
    Write-EnvoyStateFile -Value $failedState -Path $desktopStatePath -Depth 5
    if ([string]::IsNullOrWhiteSpace($activationFailCloseError)) { throw "RustDesk activation failed closed: $($activationError.Exception.Message)" }
    throw "RustDesk activation failed and requires immediate local-console investigation: $($activationError.Exception.Message) Fail-close: $activationFailCloseError"
}
Write-Output "RustDesk direct-IP access is scoped to the Tailscale adapter at $ipv4 on TCP $port; public RustDesk egress is blocked."
Write-Output "Validated signer: $($signature.SignerCertificate.Subject)"
Write-Output 'Test from the second laptop, reboot deliberately, test again, then run DesktopAcceptRebootProof with a fresh reviewed plan.'
