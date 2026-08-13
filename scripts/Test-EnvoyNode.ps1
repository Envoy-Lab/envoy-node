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
$script:WindowsSystemDirectory = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { Join-Path $env:WINDIR 'Sysnative' } else { Join-Path $env:WINDIR 'System32' }
$script:SshdExe = Join-Path $script:WindowsSystemDirectory 'OpenSSH\sshd.exe'

if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Configuration file not found: $ConfigPath" }
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$auditPorts = @([int]$config.access.ssh.port, [int]$config.access.desktop.port)
$audit = & (Join-Path $PSScriptRoot 'Get-EnvoyAudit.ps1') -AdditionalSensitivePorts $auditPorts -PassThru -NoReport
$checks = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param([string]$Id, [ValidateSet('PASS', 'WARN', 'FAIL')][string]$Status, [string]$Message)
    $checks.Add([pscustomobject][ordered]@{ id = $Id; status = $Status; message = $Message })
}

function Test-NoReparsePathChain {
    param([string]$Path)
    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
        $root = [IO.Path]::GetPathRoot($fullPath)
        if ([string]::IsNullOrWhiteSpace($root)) { return $false }
        $current = $root
        foreach ($segment in @($fullPath.Substring($root.Length) -split '[\\/]' | Where-Object { $_ })) {
            $current = Join-Path $current $segment
            if (-not (Test-Path -LiteralPath $current)) { return $false }
            if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        }
        return $true
    }
    catch { return $false }
}

function Test-SshdServiceIdentity {
    param([string]$ExpectedExecutable)
    try {
        if (-not (Test-Path -LiteralPath $ExpectedExecutable -PathType Leaf)) { return $false }
        $expectedResolved = (Resolve-Path -LiteralPath $ExpectedExecutable).Path
        if ((Get-AuthenticodeSignature -FilePath $expectedResolved).Status -ne 'Valid') { return $false }
        $services = @(Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop)
        if ($services.Count -ne 1) { return $false }
        $service = $services[0]
        $registeredCommand = [Environment]::ExpandEnvironmentVariables(([string]$service.PathName).Trim())
        if ($registeredCommand -match '^"([^\"]+)"$') { $registeredExecutable = $Matches[1] }
        elseif ($registeredCommand -match '^(\S+)$') { $registeredExecutable = $Matches[1] }
        else { return $false }
        if (-not (Test-Path -LiteralPath $registeredExecutable -PathType Leaf) -or (Resolve-Path -LiteralPath $registeredExecutable).Path -ine $expectedResolved -or [string]$service.StartName -ne 'LocalSystem') { return $false }
        if ([string]$service.State -eq 'Running') {
            if ([int]$service.ProcessId -le 0) { return $false }
            $processes = @(Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$service.ProcessId)" -ErrorAction Stop)
            if ($processes.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$processes[0].ExecutablePath)) { return $false }
            if ((Resolve-Path -LiteralPath ([string]$processes[0].ExecutablePath)).Path -ine $expectedResolved) { return $false }
        }
        return $true
    }
    catch { return $false }
}

function Get-TrustedProgramFilesAuthoritySids {
    try {
        $trusted = New-Object System.Collections.Generic.HashSet[string]
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) { $null = $trusted.Add($sid) }
        $trustedInstallerSid = (New-Object Security.Principal.NTAccount('NT SERVICE\TrustedInstaller')).Translate([Security.Principal.SecurityIdentifier]).Value
        $null = $trusted.Add($trustedInstallerSid)
        return ,$trusted
    }
    catch { return $null }
}

function Test-NoUntrustedPathMutationAcl {
    param([string]$Path)
    try {
        $trustedOwners = Get-TrustedProgramFilesAuthoritySids
        if ($null -eq $trustedOwners) { return $false }
        $trustedRules = New-Object System.Collections.Generic.HashSet[string]
        foreach ($sid in @($trustedOwners)) { $null = $trustedRules.Add([string]$sid) }
        $null = $trustedRules.Add('S-1-3-0')
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        try { $ownerSid = (New-Object Security.Principal.NTAccount($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value }
        catch { return $false }
        if (-not $trustedOwners.Contains($ownerSid)) { return $false }
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
            catch { return $false }
            $rights = [int]$rule.FileSystemRights
            $grantsMutation = ($rights -band $dangerousMask) -ne 0 -or ($rights -band 0x10000000) -ne 0 -or ($rights -band 0x40000000) -ne 0
            if ($grantsMutation -and -not $trustedRules.Contains($ruleSid)) { return $false }
        }
        return $true
    }
    catch { return $false }
}

function Test-RustDeskBinaryAuthority {
    param([string]$Executable)
    try {
        $nativeProgramFiles = if ([string]::IsNullOrWhiteSpace($env:ProgramW6432)) { $env:ProgramFiles } else { $env:ProgramW6432 }
        $programFilesPath = [IO.Path]::GetFullPath($nativeProgramFiles)
        $rustDeskRoot = [IO.Path]::GetFullPath((Join-Path $programFilesPath 'RustDesk'))
        $fullExecutable = [IO.Path]::GetFullPath($Executable)
        if (-not $fullExecutable.StartsWith($rustDeskRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { return $null }
        if (-not (Test-NoReparsePathChain -Path $fullExecutable)) { return $null }
        $resolvedExecutable = (Resolve-Path -LiteralPath $fullExecutable -ErrorAction Stop).Path
        if ($resolvedExecutable -ine $fullExecutable -or -not (Test-NoUntrustedPathMutationAcl -Path $programFilesPath)) { return $null }
        $pendingPaths = New-Object 'System.Collections.Generic.Queue[string]'
        $pendingPaths.Enqueue($rustDeskRoot)
        while ($pendingPaths.Count -gt 0) {
            $path = $pendingPaths.Dequeue()
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or -not (Test-NoUntrustedPathMutationAcl -Path $path)) { return $null }
            if ($item.PSIsContainer) {
                foreach ($child in @(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop)) { $pendingPaths.Enqueue($child.FullName) }
            }
        }
        return $resolvedExecutable
    }
    catch { return $null }
}

function Get-RustDeskServiceAccountSid {
    param([string]$StartName)
    if ($StartName -ieq 'LocalSystem' -or $StartName -ieq 'NT AUTHORITY\SYSTEM') { return 'S-1-5-18' }
    if ($StartName -ieq 'LocalService' -or $StartName -ieq 'NT AUTHORITY\LocalService' -or $StartName -ieq 'NT AUTHORITY\LOCAL SERVICE') { return 'S-1-5-19' }
    try { return (New-Object Security.Principal.NTAccount($StartName)).Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { return $null }
}

function Test-RustDeskServiceIdentity {
    param($StateObject, [switch]$RequireRunning)
    try {
        if (-not $StateObject) { return $null }
        $stateProperties = @($StateObject.PSObject.Properties.Name)
        if (@('executable', 'executableSha256', 'signer', 'serviceAccount', 'serviceAccountSid', 'serviceCommandMode', 'serverCommandMode') | Where-Object { $_ -notin $stateProperties }) { return $null }
        if ([string]$StateObject.serviceCommandMode -cne '--service' -or [string]$StateObject.serverCommandMode -cne '--server') { return $null }
        $trustedExecutable = Test-RustDeskBinaryAuthority -Executable ([string]$StateObject.executable)
        if ([string]::IsNullOrWhiteSpace([string]$trustedExecutable)) { return $null }
        $signature = Get-AuthenticodeSignature -FilePath $trustedExecutable
        if ($signature.Status -ne 'Valid' -or [string]$signature.SignerCertificate.Subject -cne [string]$StateObject.signer -or
            (Get-FileHash -LiteralPath $trustedExecutable -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$StateObject.executableSha256 -or
            (Get-Item -LiteralPath $trustedExecutable).VersionInfo.ProductName -notmatch 'RustDesk') { return $null }
        $services = @(Get-CimInstance Win32_Service -Filter "Name='RustDesk'" -ErrorAction Stop)
        if ($services.Count -ne 1) { return $null }
        $service = $services[0]
        $registeredCommand = [Environment]::ExpandEnvironmentVariables(([string]$service.PathName).Trim())
        if ($registeredCommand -notmatch '^\s*"([^"]+)"\s+--service\s*$') { return $null }
        $registeredExecutable = Test-RustDeskBinaryAuthority -Executable $Matches[1]
        $accountSid = Get-RustDeskServiceAccountSid -StartName ([string]$service.StartName)
        if ([string]::IsNullOrWhiteSpace([string]$registeredExecutable) -or $registeredExecutable -ine $trustedExecutable -or $accountSid -notin @('S-1-5-18', 'S-1-5-19') -or
            [string]$accountSid -cne [string]$StateObject.serviceAccountSid -or [string]$service.StartName -ine [string]$StateObject.serviceAccount) { return $null }
        if ($RequireRunning -and ([string]$service.State -ne 'Running' -or [int]$service.ProcessId -le 0)) { return $null }
        if ([string]$service.State -eq 'Running') {
            $processes = @(Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$service.ProcessId)" -ErrorAction Stop)
            if ($processes.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$processes[0].ExecutablePath) -or (Resolve-Path -LiteralPath ([string]$processes[0].ExecutablePath)).Path -ine $trustedExecutable) { return $null }
        }
        return [pscustomobject]@{ Service = $service; Executable = $trustedExecutable }
    }
    catch { return $null }
}

function Test-RustDeskDirectListenerIdentity {
    param($ServiceIdentity, [int]$Port, [string[]]$AllowedLocalAddresses)
    try {
        if (-not $ServiceIdentity -or [string]$ServiceIdentity.Service.State -ne 'Running' -or [int]$ServiceIdentity.Service.ProcessId -le 0) { return $null }
        $managedTcpListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { [int]$_.LocalPort -eq $Port })
        $managedUdpEndpoints = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { [int]$_.LocalPort -eq $Port })
        if ($managedTcpListeners.Count -ne 1 -or $managedUdpEndpoints.Count -ne 0 -or [string]$managedTcpListeners[0].LocalAddress -notin $AllowedLocalAddresses) { return $null }
        $listener = $managedTcpListeners[0]
        $serverProcesses = @(Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$listener.OwningProcess)" -ErrorAction Stop)
        if ($serverProcesses.Count -ne 1) { return $null }
        $serverProcess = $serverProcesses[0]
        if ([int]$serverProcess.ParentProcessId -ne [int]$ServiceIdentity.Service.ProcessId -or [string]::IsNullOrWhiteSpace([string]$serverProcess.ExecutablePath) -or
            (Resolve-Path -LiteralPath ([string]$serverProcess.ExecutablePath)).Path -ine [string]$ServiceIdentity.Executable) { return $null }
        $serverCommand = [Environment]::ExpandEnvironmentVariables(([string]$serverProcess.CommandLine).Trim())
        if ($serverCommand -notmatch '^\s*"([^"]+)"\s+--server\s*$' -or (Resolve-Path -LiteralPath $Matches[1]).Path -ine [string]$ServiceIdentity.Executable) { return $null }
        $rustDeskProcesses = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_.ExecutablePath) -and (Test-Path -LiteralPath ([string]$_.ExecutablePath) -PathType Leaf) -and
            (Resolve-Path -LiteralPath ([string]$_.ExecutablePath)).Path -ieq [string]$ServiceIdentity.Executable
        })
        $rustDeskProcessIds = @($rustDeskProcesses.ProcessId | ForEach-Object { [int]$_ })
        $allRustDeskTcpListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { [int]$_.OwningProcess -in $rustDeskProcessIds })
        if ($allRustDeskTcpListeners.Count -ne 1 -or [int]$allRustDeskTcpListeners[0].OwningProcess -ne [int]$serverProcess.ProcessId -or [int]$allRustDeskTcpListeners[0].LocalPort -ne $Port) { return $null }
        return [pscustomobject]@{ ServerProcess = $serverProcess; Listener = $listener }
    }
    catch { return $null }
}

function Test-ExactStandardSshDirectoryAcl {
    param([string]$Path, [string]$TargetSid)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Container) -or -not (Test-NoReparsePathChain -Path $Path)) { return $false }
        $acl = Get-Acl -LiteralPath $Path
        try { $ownerSid = (New-Object Security.Principal.NTAccount($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value }
        catch { return $false }
        $allowedSids = @($TargetSid, 'S-1-5-18', 'S-1-5-32-544')
        if ($ownerSid -ne $TargetSid -or -not $acl.AreAccessRulesProtected -or @($acl.Access).Count -ne $allowedSids.Count) { return $false }
        $seen = New-Object System.Collections.Generic.HashSet[string]
        $expectedInheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        foreach ($rule in @($acl.Access)) {
            try { $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
            catch { return $false }
            if ($rule.IsInherited -or $sid -notin $allowedSids -or [string]$rule.AccessControlType -ne 'Allow' -or
                [int]$rule.FileSystemRights -ne [int][Security.AccessControl.FileSystemRights]::FullControl -or
                $rule.InheritanceFlags -ne $expectedInheritance -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { return $false }
            $null = $seen.Add($sid)
        }
        return [bool]($seen.Count -eq $allowedSids.Count -and @($allowedSids | Where-Object { -not $seen.Contains($_) }).Count -eq 0)
    }
    catch { return $false }
}

function Get-PublicKeyFingerprintToken {
    param([string]$PublicKeyLine)
    try {
        if ($PublicKeyLine -notmatch '^(ssh-ed25519|sk-ssh-ed25519@openssh\.com)\s+([A-Za-z0-9+/=]+)(?:\s+.*)?$') { return $null }
        $blob = [Convert]::FromBase64String($Matches[2])
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return 'SHA256:' + [Convert]::ToBase64String($sha.ComputeHash($blob)).TrimEnd('=') }
        finally { $sha.Dispose() }
    }
    catch { return $null }
}

function Test-FirewallRecordAppliesToProgram {
    param($Record, [string]$ProgramPath, [string]$ServiceName)
    $programs = @($Record.Program | ForEach-Object { [Environment]::ExpandEnvironmentVariables([string]$_) })
    $services = @($Record.Service | ForEach-Object { [string]$_ })
    $programApplies = $programs.Count -eq 0 -or [bool]($programs | Where-Object { $_ -in @('Any', '*') -or $_ -ieq $ProgramPath })
    $serviceApplies = $services.Count -eq 0 -or [bool]($services | Where-Object { $_ -in @('Any', '*') -or $_ -ieq $ServiceName })
    return [bool]($programApplies -and $serviceApplies)
}

function Get-NormalizedFirewallValues {
    param($Value, [switch]$ExpandEnvironment)
    return @(@($Value) | ForEach-Object {
        foreach ($item in @(([string]$_) -split ',')) {
            $text = $item.Trim()
            if ($ExpandEnvironment) { $text = [Environment]::ExpandEnvironmentVariables($text) }
            if (-not [string]::IsNullOrWhiteSpace($text)) { $text }
        }
    } | Sort-Object -Unique)
}

function Test-ExactFirewallValues {
    param($Actual, [string[]]$Expected, [switch]$ExpandEnvironment)
    $actualValues = @(Get-NormalizedFirewallValues -Value $Actual -ExpandEnvironment:$ExpandEnvironment)
    $expectedValues = @(Get-NormalizedFirewallValues -Value $Expected -ExpandEnvironment:$ExpandEnvironment)
    return [bool]($actualValues.Count -eq $expectedValues.Count -and @(Compare-Object $actualValues $expectedValues).Count -eq 0)
}

function Test-ExactPortRecord {
    param($Record, [int]$Port)
    $tokens = @(Get-NormalizedFirewallValues -Value $Record.LocalPortSpecification)
    return [bool]($tokens.Count -eq 1 -and $tokens[0] -match '^[0-9]+$' -and [int]$tokens[0] -eq $Port)
}

function Test-FirewallRuleFullyEnforced {
    param($RuleOrRecord)
    $values = @(Get-NormalizedFirewallValues -Value $RuleOrRecord.EnforcementStatus)
    return [bool]($values.Count -eq 1 -and $values[0] -in @('Full', 'Enforced', '1'))
}

function Test-DefaultFirewallSecurityDimensions {
    param($Port, $Application, $Security, $Rule)
    return [bool](
        (Test-ExactFirewallValues -Actual $Port.IcmpType -Expected @('Any')) -and
        (Test-ExactFirewallValues -Actual $Port.DynamicTarget -Expected @('Any')) -and
        (Test-ExactFirewallValues -Actual $Port.DynamicTransport -Expected @('Any')) -and
        @($Application.Package | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -eq 0 -and
        (Test-ExactFirewallValues -Actual $Security.Authentication -Expected @('NotRequired')) -and
        (Test-ExactFirewallValues -Actual $Security.Encryption -Expected @('NotRequired')) -and
        (Test-ExactFirewallValues -Actual $Security.LocalUser -Expected @('Any')) -and
        (Test-ExactFirewallValues -Actual $Security.RemoteUser -Expected @('Any')) -and
        (Test-ExactFirewallValues -Actual $Security.RemoteMachine -Expected @('Any')) -and
        (Test-ExactFirewallValues -Actual $Security.OverrideBlockRules -Expected @('False')) -and
        [string]$Rule.EdgeTraversalPolicy -eq 'Block' -and -not [bool]$Rule.LooseSourceMapping -and -not [bool]$Rule.LocalOnlyMapping -and
        [string]::IsNullOrWhiteSpace([string]$Rule.Owner) -and [string]::IsNullOrWhiteSpace([string]$Rule.PackageFamilyName) -and
        [string]::IsNullOrWhiteSpace([string]$Rule.PolicyAppId) -and @($Rule.RemoteDynamicKeywordAddresses | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -eq 0 -and
        [string]$Rule.PolicyStoreSourceType -eq 'Local' -and [string]$Rule.PolicyStoreSource -eq 'PersistentStore' -and
        @($Rule.Platforms | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -eq 0
    )
}

function Test-ExactInboundAuditRule {
    param($Record, [int]$Port, [string]$ProgramPath, [string]$LocalAddress, [string]$RemoteAddress, [string]$InterfaceAlias)
    return [bool](
        $Record.Group -eq 'EnvoyNode' -and $Record.Direction -eq 'Inbound' -and
        $Record.Enabled -eq 'True' -and $Record.Action -eq 'Allow' -and
        $Record.PrimaryStatus -eq 'OK' -and (Test-FirewallRuleFullyEnforced -RuleOrRecord $Record) -and
        $Record.Protocol -in @('TCP', '6') -and $Record.Profile -eq 'Any' -and
        (Test-ExactPortRecord -Record $Record -Port $Port) -and
        (Test-ExactFirewallValues -Actual $Record.RemotePortSpecification -Expected @('Any')) -and
        (Test-ExactFirewallValues -Actual $Record.Program -Expected @($ProgramPath) -ExpandEnvironment) -and
        (Test-ExactFirewallValues -Actual $Record.Service -Expected @('Any')) -and
        (Test-ExactFirewallValues -Actual $Record.LocalAddress -Expected @($LocalAddress)) -and
        (Test-ExactFirewallValues -Actual $Record.RemoteAddress -Expected @($RemoteAddress)) -and
        (Test-ExactFirewallValues -Actual $Record.InterfaceAlias -Expected @($InterfaceAlias)) -and
        (Test-ExactFirewallValues -Actual $Record.InterfaceType -Expected @('Any')) -and
        (Test-DefaultFirewallSecurityDimensions -Port ([pscustomobject]@{ IcmpType = $Record.IcmpType; DynamicTarget = $Record.DynamicTarget; DynamicTransport = $Record.DynamicTransport }) -Application ([pscustomobject]@{ Package = $Record.Package }) -Security ([pscustomobject]@{ Authentication = $Record.Authentication; Encryption = $Record.Encryption; LocalUser = $Record.LocalUser; RemoteUser = $Record.RemoteUser; RemoteMachine = $Record.RemoteMachine; OverrideBlockRules = $Record.OverrideBlockRules }) -Rule $Record)
    )
}

function Get-LiveFirewallRuleSnapshot {
    param([string]$Name)
    $rules = @(Get-NetFirewallRule -Name $Name -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop)
    if ($rules.Count -ne 1) { throw "Expected exactly one firewall rule named '$Name'." }
    $rule = $rules[0]
    return [pscustomobject]@{
        Rule = $rule
        Port = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
        Address = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
        Interface = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
        InterfaceType = @(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
        Application = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
        Service = @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
        Security = @(Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
    }
}

function Test-ExactLiveInboundRule {
    param($Snapshot, [int]$Port, [string]$ProgramPath, [string]$LocalAddress, [string]$RemoteAddress, [string]$InterfaceAlias)
    if ($Snapshot.Port.Count -ne 1 -or $Snapshot.Address.Count -ne 1 -or $Snapshot.Interface.Count -ne 1 -or $Snapshot.InterfaceType.Count -ne 1 -or $Snapshot.Application.Count -ne 1 -or $Snapshot.Service.Count -ne 1 -or $Snapshot.Security.Count -ne 1) { return $false }
    $rule = $Snapshot.Rule
    $portFilter = $Snapshot.Port[0]
    return [bool](
        $rule.Group -eq 'EnvoyNode' -and [string]$rule.Direction -eq 'Inbound' -and
        [string]$rule.Enabled -eq 'True' -and [string]$rule.Action -eq 'Allow' -and [string]$rule.Profile -eq 'Any' -and
        [string]$rule.PrimaryStatus -eq 'OK' -and (Test-FirewallRuleFullyEnforced -RuleOrRecord $rule) -and
        [string]$portFilter.Protocol -in @('TCP', '6') -and
        (Test-ExactFirewallValues -Actual $portFilter.LocalPort -Expected @([string]$Port)) -and
        (Test-ExactFirewallValues -Actual $portFilter.RemotePort -Expected @('Any')) -and
        (Test-ExactFirewallValues -Actual $Snapshot.Application[0].Program -Expected @($ProgramPath) -ExpandEnvironment) -and
        (Test-ExactFirewallValues -Actual $Snapshot.Service[0].Service -Expected @('Any')) -and
        (Test-ExactFirewallValues -Actual $Snapshot.Address[0].LocalAddress -Expected @($LocalAddress)) -and
        (Test-ExactFirewallValues -Actual $Snapshot.Address[0].RemoteAddress -Expected @($RemoteAddress)) -and
        (Test-ExactFirewallValues -Actual $Snapshot.Interface[0].InterfaceAlias -Expected @($InterfaceAlias)) -and
        (Test-ExactFirewallValues -Actual $Snapshot.InterfaceType[0].InterfaceType -Expected @('Any')) -and
        (Test-DefaultFirewallSecurityDimensions -Port $Snapshot.Port[0] -Application $Snapshot.Application[0] -Security $Snapshot.Security[0] -Rule $rule)
    )
}

function Test-ExactLiveOutboundBlockRule {
    param($Snapshot, [string]$ProgramPath, [string[]]$RemoteAddresses)
    if ($Snapshot.Port.Count -ne 1 -or $Snapshot.Address.Count -ne 1 -or $Snapshot.Interface.Count -ne 1 -or $Snapshot.InterfaceType.Count -ne 1 -or $Snapshot.Application.Count -ne 1 -or $Snapshot.Service.Count -ne 1 -or $Snapshot.Security.Count -ne 1) { return $false }
    $rule = $Snapshot.Rule
    return [bool](
        $rule.Group -eq 'EnvoyNode' -and [string]$rule.Direction -eq 'Outbound' -and
        [string]$rule.Enabled -eq 'True' -and [string]$rule.Action -eq 'Block' -and [string]$rule.Profile -eq 'Any' -and
        [string]$rule.PrimaryStatus -eq 'OK' -and (Test-FirewallRuleFullyEnforced -RuleOrRecord $rule) -and
        [string]$Snapshot.Port[0].Protocol -in @('Any', '256') -and
        (Test-ExactFirewallValues -Actual $Snapshot.Port[0].LocalPort -Expected @('Any')) -and
        (Test-ExactFirewallValues -Actual $Snapshot.Port[0].RemotePort -Expected @('Any')) -and
        (Test-ExactFirewallValues -Actual $Snapshot.Application[0].Program -Expected @($ProgramPath) -ExpandEnvironment) -and
        (Test-ExactFirewallValues -Actual $Snapshot.Service[0].Service -Expected @('Any')) -and
        (Test-ExactFirewallValues -Actual $Snapshot.Address[0].LocalAddress -Expected @('Any')) -and
        (Test-ExactFirewallValues -Actual $Snapshot.Address[0].RemoteAddress -Expected $RemoteAddresses) -and
        (Test-ExactFirewallValues -Actual $Snapshot.Interface[0].InterfaceAlias -Expected @('Any')) -and
        (Test-ExactFirewallValues -Actual $Snapshot.InterfaceType[0].InterfaceType -Expected @('Any')) -and
        (Test-DefaultFirewallSecurityDimensions -Port $Snapshot.Port[0] -Application $Snapshot.Application[0] -Security $Snapshot.Security[0] -Rule $rule)
    )
}

function Test-SafeUnmanagedSshConfig {
    param([string]$ConfigPathOnHost)
    try {
        $text = [IO.File]::ReadAllText($ConfigPathOnHost)
        $managedPattern = '(?ms)^# BEGIN EnvoyNode managed global settings\r?\n.*?^# END EnvoyNode managed global settings\r?\n?'
        if (@([regex]::Matches($text, $managedPattern)).Count -ne 1) { return $false }
        $unmanaged = [regex]::Replace($text, $managedPattern, '', 1)
        $active = @($unmanaged -split "`r?`n" | ForEach-Object { ($_ -replace '\s+#.*$', '').Trim() } | Where-Object { $_ })
        if (@($active | Where-Object { $_ -match '(?i)^Include\s+' }).Count -gt 0) { return $false }
        if (@($active | Where-Object { $_ -match '(?i)^(AuthorizedKeysCommand|AuthorizedKeysCommandUser|AuthorizedPrincipalsCommand|AuthorizedPrincipalsCommandUser)\s+' }).Count -gt 0) { return $false }
        $matchIndexes = @(for ($i = 0; $i -lt $active.Count; $i++) { if ($active[$i] -match '(?i)^Match\s+') { $i } })
        if ($matchIndexes.Count -gt 1) { return $false }
        if ($matchIndexes.Count -eq 1) {
            $matchIndex = [int]$matchIndexes[0]
            $matchLine = (($active[$matchIndex] -replace '\s+', ' ').Trim())
            $tail = if ($matchIndex -lt ($active.Count - 1)) { @($active[($matchIndex + 1)..($active.Count - 1)] | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) }) } else { @() }
            if ($matchLine -ine 'Match Group administrators' -or $tail.Count -ne 1 -or $tail[0] -ine 'AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys') { return $false }
        }
        return $true
    }
    catch { return $false }
}

function Test-EffectiveSshConfiguration {
    param([string]$Executable, [string]$ConfigPathOnHost, $Config, [string]$UserName, [string]$AuthorizedKeysPath, [string]$SourceAddress, [string]$LocalAddress)
    try {
        $prior = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $effectiveText = (& $Executable -T -f $ConfigPathOnHost -C "user=$UserName,host=localhost,addr=127.0.0.1" 2>&1 | Out-String).Trim()
            $code = $LASTEXITCODE
        }
        finally { $ErrorActionPreference = $prior }
        if ($code -ne 0) { return $false }
        $settings = @{}
        foreach ($line in @($effectiveText -split "`r?`n")) {
            if ($line -match '^([^\s]+)\s+(.*)$') {
                $name = $Matches[1].ToLowerInvariant()
                $settings[$name] = @($settings[$name]) + $Matches[2].Trim()
            }
        }
        $expectedScalars = [ordered]@{
            pubkeyauthentication = 'yes'; passwordauthentication = 'no'
            authenticationmethods = 'publickey'; allowagentforwarding = 'no'
            authorizedkeysfile = $AuthorizedKeysPath.Replace('\', '/'); trustedusercakeys = 'none'
            gssapiauthentication = 'no'
            allowtcpforwarding = if ($Config.access.ssh.allowLocalPortForwarding) { 'local' } else { 'no' }
            gatewayports = 'no'; permitemptypasswords = 'no'; maxauthtries = '3'; logingracetime = '30'; loglevel = 'verbose'
        }
        foreach ($entry in $expectedScalars.GetEnumerator()) {
            $observed = @($settings[$entry.Key] | Sort-Object -Unique)
            if ($observed.Count -ne 1 -or $observed[0] -ine [string]$entry.Value) { return $false }
        }
        $ports = @($settings['port'] | ForEach-Object { @($_ -split '\s+') } | Where-Object { $_ } | Sort-Object -Unique)
        if ($ports.Count -ne 1 -or $ports[0] -ne [string][int]$Config.access.ssh.port) { return $false }
        foreach ($listenAddress in @($settings['listenaddress'])) {
            if ($listenAddress -notmatch ':(\d+)$' -or [int]$Matches[1] -ne [int]$Config.access.ssh.port) { return $false }
        }
        $allowedUsers = @($settings['allowusers'] | ForEach-Object { @($_ -split '\s+') } | Where-Object { $_ } | Sort-Object -Unique)
        if ($allowedUsers.Count -ne 1 -or $allowedUsers[0] -ine $UserName) { return $false }
        $expectedPermitOpen = if ($Config.access.ssh.allowLocalPortForwarding -and @($Config.access.ssh.allowedForwardTargets).Count -gt 0) { @($Config.access.ssh.allowedForwardTargets) } else { @('none') }
        $actualPermitOpen = @($settings['permitopen'] | ForEach-Object { @($_ -split '\s+') } | Where-Object { $_ } | Sort-Object -Unique)
        $expectedPermitOpen = @($expectedPermitOpen | Sort-Object -Unique)
        if ($actualPermitOpen.Count -ne $expectedPermitOpen.Count -or @(Compare-Object $actualPermitOpen $expectedPermitOpen).Count -ne 0) { return $false }
        if ($SourceAddress -and $LocalAddress) {
            $ErrorActionPreference = 'Continue'
            $tailnetText = (& $Executable -T -f $ConfigPathOnHost -C "user=$UserName,host=envoynode,addr=$SourceAddress,laddr=$LocalAddress,lport=$([int]$Config.access.ssh.port)" 2>&1 | Out-String).Trim()
            $tailnetCode = $LASTEXITCODE
            $ErrorActionPreference = $prior
            if ($tailnetCode -ne 0 -or ($tailnetText -replace "`r`n", "`n").Trim() -cne ($effectiveText -replace "`r`n", "`n").Trim()) { return $false }
        }
        return $true
    }
    catch { return $false }
}

function Test-AuthorizedKeyAllowlist {
    param($StateObject, $Config, [string]$ConfigPathOnHost, [string]$MachineFingerprint)
    try {
        if (-not $StateObject) { return $false }
        $properties = @($StateObject.PSObject.Properties.Name)
        $required = @('schemaVersion', 'machineFingerprint', 'targetUser', 'targetSid', 'targetIsAdministrator', 'sshPort', 'authorizedKeysPath', 'approvedKeyCount', 'publicKeyFingerprints')
        if (@($required | Where-Object { $_ -notin $properties }).Count -gt 0 -or $StateObject.schemaVersion -ne 1 -or $StateObject.machineFingerprint -ne $MachineFingerprint) { return $false }
        $desiredTargetName = if ([string]::IsNullOrWhiteSpace([string]$Config.access.ssh.targetUser)) { $env:USERNAME } else { [string]$Config.access.ssh.targetUser }
        $desiredTargetAccount = Get-LocalUser -Name $desiredTargetName -ErrorAction Stop
        $administratorMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
        $desiredTargetIsAdministrator = [bool]($administratorMembers | Where-Object { $_.SID.Value -eq $desiredTargetAccount.SID.Value })
        if ([string]$StateObject.targetUser -ine [string]$desiredTargetAccount.Name -or
            [string]$StateObject.targetSid -cne [string]$desiredTargetAccount.SID.Value -or
            [bool]$StateObject.targetIsAdministrator -ne $desiredTargetIsAdministrator) { return $false }
        $targetAccount = Get-LocalUser -Name ([string]$StateObject.targetUser) -ErrorAction Stop
        if ($targetAccount.SID.Value -ne [string]$StateObject.targetSid) { return $false }
        if ([int]$StateObject.sshPort -ne [int]$Config.access.ssh.port) { return $false }
        $authorizedPath = [string]$StateObject.authorizedKeysPath
        if (-not (Test-Path -LiteralPath $authorizedPath) -or -not (Test-NoReparsePathChain -Path $authorizedPath)) { return $false }
        if (-not [bool]$StateObject.targetIsAdministrator -and -not (Test-ExactStandardSshDirectoryAcl -Path (Split-Path $authorizedPath -Parent) -TargetSid ([string]$StateObject.targetSid))) { return $false }
        $configDirectory = Split-Path (Resolve-Path -LiteralPath $ConfigPathOnHost).Path -Parent
        $desiredLines = New-Object System.Collections.Generic.List[string]
        $desiredTokens = New-Object System.Collections.Generic.List[string]
        foreach ($configuredPath in @($Config.access.ssh.publicKeyFiles)) {
            $candidate = [string]$configuredPath
            if ([string]::IsNullOrWhiteSpace($candidate)) { return $false }
            if (-not [IO.Path]::IsPathRooted($candidate)) { $candidate = Join-Path $configDirectory $candidate }
            if (-not (Test-Path -LiteralPath $candidate)) { return $false }
            $line = (Get-Content -LiteralPath $candidate -Raw).Trim()
            if ($line -notmatch '^(ssh-ed25519|sk-ssh-ed25519@openssh\.com)\s+[A-Za-z0-9+/=]+(?:\s+.*)?$' -or $desiredLines.Contains($line)) { return $false }
            $token = Get-PublicKeyFingerprintToken -PublicKeyLine $line
            if ([string]::IsNullOrWhiteSpace($token) -or $desiredTokens.Contains($token)) { return $false }
            $desiredLines.Add($line)
            $desiredTokens.Add($token)
        }
        $actualLines = @(Get-Content -LiteralPath $authorizedPath | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($desiredLines.Count -eq 0 -or $actualLines.Count -ne $desiredLines.Count -or @(Compare-Object @($desiredLines) $actualLines).Count -ne 0 -or [int]$StateObject.approvedKeyCount -ne $desiredLines.Count) { return $false }
        $actualTokens = @($actualLines | ForEach-Object { Get-PublicKeyFingerprintToken -PublicKeyLine $_ } | Where-Object { $_ } | Sort-Object -Unique)
        $stateTokens = New-Object System.Collections.Generic.List[string]
        foreach ($stateFingerprint in @($StateObject.publicKeyFingerprints)) {
            if ([string]$stateFingerprint -notmatch '(SHA256:[A-Za-z0-9+/]+)') { return $false }
            if ($stateTokens.Contains($Matches[1])) { return $false }
            $stateTokens.Add($Matches[1])
        }
        $desiredSorted = @($desiredTokens | Sort-Object)
        $stateSorted = @($stateTokens | Sort-Object)
        if ($actualTokens.Count -ne $desiredLines.Count -or $stateTokens.Count -ne $desiredLines.Count -or
            @(Compare-Object $desiredSorted $actualTokens).Count -ne 0 -or @(Compare-Object $desiredSorted $stateSorted).Count -ne 0) { return $false }
        if ((Get-Item -LiteralPath $authorizedPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        $acl = Get-Acl -LiteralPath $authorizedPath
        $allowedSids = if ($StateObject.targetIsAdministrator) { @('S-1-5-18', 'S-1-5-32-544') } else { @('S-1-5-18', 'S-1-5-32-544', [string]$StateObject.targetSid) }
        if (-not $acl.AreAccessRulesProtected -or @($acl.Access).Count -ne $allowedSids.Count) { return $false }
        $seenSids = New-Object System.Collections.Generic.HashSet[string]
        foreach ($rule in @($acl.Access)) {
            try { $ruleSid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { return $false }
            if ($rule.IsInherited -or $ruleSid -notin $allowedSids -or [string]$rule.AccessControlType -ne 'Allow' -or
                [int]$rule.FileSystemRights -ne [int][Security.AccessControl.FileSystemRights]::FullControl -or
                $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { return $false }
            $null = $seenSids.Add($ruleSid)
        }
        return [bool]($seenSids.Count -eq $allowedSids.Count -and @($allowedSids | Where-Object { -not $seenSids.Contains($_) }).Count -eq 0)
    }
    catch { return $false }
}

function Test-PrivilegedStateAcl {
    param([string]$DirectoryPath, [string[]]$RequiredFiles, [switch]$SkipParentDirectory)
    try {
        $allowedSids = @('S-1-5-18', 'S-1-5-32-544')
        $fullControl = [int][Security.AccessControl.FileSystemRights]::FullControl
        $directoryInheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        $directories = if ($SkipParentDirectory) { @($DirectoryPath) } else { @((Split-Path $DirectoryPath -Parent), $DirectoryPath) }
        foreach ($directory in $directories) {
            if (-not (Test-Path -LiteralPath $directory -PathType Container)) { return $false }
            if ((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
            $directoryAcl = Get-Acl -LiteralPath $directory
            if (-not $directoryAcl.AreAccessRulesProtected -or @($directoryAcl.Access).Count -ne 2) { return $false }
            try { $directoryOwnerSid = (New-Object Security.Principal.NTAccount($directoryAcl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { return $false }
            if ($directoryOwnerSid -ne 'S-1-5-32-544') { return $false }
            $seenDirectorySids = New-Object System.Collections.Generic.HashSet[string]
            foreach ($rule in @($directoryAcl.Access)) {
                try { $ruleSid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { return $false }
                if ($rule.IsInherited -or $ruleSid -notin $allowedSids -or [string]$rule.AccessControlType -ne 'Allow' -or [int]$rule.FileSystemRights -ne $fullControl -or $rule.InheritanceFlags -ne $directoryInheritance -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { return $false }
                $null = $seenDirectorySids.Add($ruleSid)
            }
            if ($seenDirectorySids.Count -ne 2 -or @($allowedSids | Where-Object { -not $seenDirectorySids.Contains($_) }).Count -gt 0) { return $false }
        }
        foreach ($requiredFile in $RequiredFiles) {
            if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) { return $false }
            if ((Get-Item -LiteralPath $requiredFile -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
            $fileAcl = Get-Acl -LiteralPath $requiredFile
            if (-not $fileAcl.AreAccessRulesProtected -or @($fileAcl.Access).Count -ne 2) { return $false }
            try { $fileOwnerSid = (New-Object Security.Principal.NTAccount($fileAcl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { return $false }
            if ($fileOwnerSid -ne 'S-1-5-32-544') { return $false }
            $seenFileSids = New-Object System.Collections.Generic.HashSet[string]
            foreach ($rule in @($fileAcl.Access)) {
                try { $ruleSid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { return $false }
                if ($rule.IsInherited -or $ruleSid -notin $allowedSids -or [string]$rule.AccessControlType -ne 'Allow' -or [int]$rule.FileSystemRights -ne $fullControl -or $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { return $false }
                $null = $seenFileSids.Add($ruleSid)
            }
            if ($seenFileSids.Count -ne 2 -or @($allowedSids | Where-Object { -not $seenFileSids.Contains($_) }).Count -gt 0) { return $false }
        }
        return $true
    }
    catch { return $false }
}

function Test-SshConfigurationAuthority {
    param([string]$DirectoryPath, [string]$ConfigPath)
    try {
        $expectedDirectory = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'ssh'))
        $expectedConfig = [IO.Path]::GetFullPath((Join-Path $expectedDirectory 'sshd_config'))
        if ([IO.Path]::GetFullPath($DirectoryPath) -ine $expectedDirectory -or [IO.Path]::GetFullPath($ConfigPath) -ine $expectedConfig) { return $false }
        if (-not (Test-NoReparsePathChain -Path $expectedDirectory) -or -not (Test-NoReparsePathChain -Path $expectedConfig)) { return $false }
        return (Test-PrivilegedStateAcl -DirectoryPath $expectedDirectory -RequiredFiles @($expectedConfig) -SkipParentDirectory)
    }
    catch { return $false }
}

if ($config.access.exposePublicPorts -eq $false) { Add-Check 'no-public-ports-config' 'PASS' 'Configuration forbids public ports.' }
else { Add-Check 'no-public-ports-config' 'FAIL' 'Configuration permits public ports.' }
if ($config.access.overlay.unattended -eq $true -and $config.access.overlay.requireMfa -eq $true -and $config.access.overlay.requireDeviceApproval -eq $true) { Add-Check 'tailnet-policy-config' 'PASS' 'Current configuration still requires unattended host mode, MFA, and device approval.' }
else { Add-Check 'tailnet-policy-config' 'FAIL' 'Current configuration must require unattended host mode, MFA, and device approval. Admin-console enforcement remains a human attestation.' }
if (-not $config.access.desktop.enabled -or ($config.access.desktop.provider -eq 'rustdesk-direct' -and $config.access.desktop.requireTailnetWhitelist -eq $true -and $config.access.desktop.blockPublicRustDeskEgress -eq $true -and $config.access.desktop.disableLanDiscovery -eq $true -and $config.access.desktop.disableRemoteConfiguration -eq $true)) { Add-Check 'desktop-security-config' 'PASS' 'Optional desktop is off or requires the complete private RustDesk configuration.' }
else { Add-Check 'desktop-security-config' 'FAIL' 'Enabled desktop control must require the tailnet whitelist, public-egress blocks, disabled LAN discovery, and disabled remote configuration.' }
if ($config.safety.requirePlanReview -eq $true) { Add-Check 'plan-review-policy' 'PASS' 'Mutating entry points require a fresh, machine-bound reviewed plan artifact and matching approval hash.' }
else { Add-Check 'plan-review-policy' 'FAIL' 'safety.requirePlanReview must remain enabled for strict acceptance.' }
if ($audit.management.inspectionComplete -and -not $audit.management.managedDeviceOrPolicy) { Add-Check 'managed-device-policy' 'PASS' 'Domain, Entra ID/workplace join, MDM enrollment, and managed firewall/OpenSSH/RustDesk policy were inspected and are absent.' }
else { Add-Check 'managed-device-policy' 'FAIL' 'Device-management inspection is incomplete or an enterprise/domain/Entra/workplace/MDM/managed-policy authority is present; mutations must stop.' }

if ($audit.access.portProxyInspectionComplete -and -not $audit.access.localPortProxyConfigured) { Add-Check 'no-windows-portproxy' 'PASS' 'Windows port-proxy forwarding was inspected and no rule exists.' }
else { Add-Check 'no-windows-portproxy' 'FAIL' 'Strict acceptance forbids every Windows port-proxy rule and requires a complete inspection.' }

if (-not $audit.access.firewallInspectionComplete) { Add-Check 'managed-port-firewall-scope' 'FAIL' 'Strict acceptance requires a complete elevated firewall inspection.' }
else { Add-Check 'managed-port-firewall-scope' 'PASS' 'Managed-port firewall rules were fully inspected, including Any/list/range port specifications.' }
if ($audit.access.firewallProfilesSecure) { Add-Check 'windows-firewall-profiles' 'PASS' 'All Windows Firewall profiles are enabled with default inbound blocking.' }
else { Add-Check 'windows-firewall-profiles' 'FAIL' 'Every Windows Firewall profile must be enabled with default inbound blocking.' }

if ($config.access.overlay.provider -eq 'tailscale') {
    if ($audit.access.tailscale.installationTrusted -and $audit.access.tailscale.versionSupportsKeyExpiry -and $audit.access.tailscale.online -and $audit.access.tailscale.serviceStatus -eq 'Running' -and $audit.access.tailscale.serviceStartType -eq 'Automatic' -and $audit.access.tailscale.preferencesVerified -and $audit.access.tailscale.unattendedMode -and $audit.access.tailscale.unsafeServerFeaturesOff -and $audit.access.tailscale.incomingConnectionsEnabled) { Add-Check 'tailscale-online' 'PASS' 'The signed fixed-path Tailscale installation is online, automatic, unattended, accepts incoming tailnet connections, and has no unexpected server/exit/subnet/remote-management features.' }
    else { Add-Check 'tailscale-online' 'FAIL' 'Tailscale online, automatic, unattended, incoming-connectivity, and least-feature preferences are not all proven.' }
    if ($audit.access.tailscale.versionMeetsSecurityFloor -and $audit.access.tailscale.serveInspectionComplete -and $audit.access.tailscale.serveConfigEmpty -and $audit.access.tailscale.funnelInspectionComplete -and $audit.access.tailscale.funnelConfigEmpty -and $audit.access.tailscale.servicesInspectionComplete -and $audit.access.tailscale.servicesConfigEmpty -and $audit.access.tailscale.driveInspectionComplete -and $audit.access.tailscale.driveSharesEmpty) { Add-Check 'tailscale-forwarding-empty' 'PASS' 'Tailscale meets the 1.98.9 security floor; Serve, public Funnel, Services forwarding, and local Taildrive shares were conclusively inspected and are empty.' }
    else { Add-Check 'tailscale-forwarding-empty' 'FAIL' 'Tailscale 1.98.9+ must conclusively report empty Serve, Funnel, Services, and Taildrive share state; these unnecessary surfaces are forbidden for this node.' }
    $expiryPolicy = [string]$config.access.overlay.hostKeyExpiry
    $expiryReady = $false
    $expiryDetail = $null
    if ($expiryPolicy -eq 'keep-enabled' -and $audit.access.tailscale.nodeKeyExpiryMode -eq 'enabled' -and -not $audit.access.tailscale.nodeKeyExpired -and -not [string]::IsNullOrWhiteSpace([string]$audit.access.tailscale.nodeKeyExpiryUtc)) {
        try {
            $expiryTime = [DateTime]::Parse([string]$audit.access.tailscale.nodeKeyExpiryUtc).ToUniversalTime()
            $expiryReady = $expiryTime -ge [DateTime]::UtcNow.AddDays(30)
            $expiryDetail = "Node-key expiry remains enabled and is outside the 30-day readiness window ($($expiryTime.ToString('o')))."
        }
        catch { $expiryReady = $false }
    }
    elseif ($expiryPolicy -eq 'disable-for-unattended-host' -and $audit.access.tailscale.nodeKeyExpiryMode -eq 'disabled') {
        $expiryReady = $true
        $expiryDetail = 'Node-key expiry is explicitly disabled for this unattended host; revocation and device approval remain operator responsibilities.'
    }
    if ($expiryReady) { Add-Check 'tailscale-node-key-expiry' 'PASS' $expiryDetail }
    else { Add-Check 'tailscale-node-key-expiry' 'FAIL' "Tailscale node-key expiry does not match policy '$expiryPolicy', is expired, is unknown, or falls inside 30 days." }
}

if ($config.access.ssh.enabled) {
    if ($audit.access.openssh.serverServicePresent -and $audit.access.openssh.serverStatus -eq 'Running' -and $audit.access.openssh.serverStartType -eq 'Automatic') { Add-Check 'sshd-running' 'PASS' 'Windows OpenSSH Server is running and starts automatically.' }
    else { Add-Check 'sshd-running' 'FAIL' 'SSH is desired but sshd is not running with automatic startup.' }
    if (Test-SshdServiceIdentity -ExpectedExecutable $script:SshdExe) { Add-Check 'sshd-service-identity' 'PASS' 'The sshd service uses the signed fixed Windows OpenSSH binary, LocalSystem, no alternate command arguments, and the matching live process path.' }
    else { Add-Check 'sshd-service-identity' 'FAIL' 'The sshd service registration, account, signature, command arguments, or live process path does not exactly match the fixed Windows OpenSSH binary.' }
    $privilegedStateDir = Join-Path $env:ProgramData 'EnvoyNode\state'
    $accessStatePath = Join-Path $privilegedStateDir 'access-current.json'
    $sshConfigDirectory = Join-Path $env:ProgramData 'ssh'
    $sshdConfigPath = Join-Path $sshConfigDirectory 'sshd_config'
    $sshdConfigAuthorityReady = Test-SshConfigurationAuthority -DirectoryPath $sshConfigDirectory -ConfigPath $sshdConfigPath
    $accessHardened = $false
    $authorizedKeysReady = $false
    $accessState = $null
    if (Test-Path -LiteralPath $accessStatePath) {
        try {
            $accessState = Get-Content -LiteralPath $accessStatePath -Raw | ConvertFrom-Json
            $accessHardened = $accessState.machineFingerprint -eq $audit.machineFingerprint -and $accessState.status -eq 'hardened-key-only' -and $accessState.authenticationMode -eq 'key-only' -and $accessState.tailnetControlsAcknowledged
            $authorizedKeysReady = Test-AuthorizedKeyAllowlist -StateObject $accessState -Config $config -ConfigPathOnHost $ConfigPath -MachineFingerprint $audit.machineFingerprint
            $accessHardened = $accessHardened -and $authorizedKeysReady
        }
        catch { }
    }
    $tailscaleAdapterBindingReady = $false
    if ($accessState -and [int]$audit.access.tailscale.adapterCount -eq 1) {
        try {
            $liveAdapter = @($audit.access.tailscale.adapters)[0]
            $liveIp = Get-NetIPAddress -IPAddress ([string]$accessState.tailscaleIPv4) -ErrorAction Stop
            $tailscaleAdapterBindingReady = [string]$liveAdapter.Status -eq 'Up' -and
                [string]$liveAdapter.Name -ceq [string]$accessState.tailscaleAdapter -and
                [int]$liveAdapter.ifIndex -eq [int]$liveIp.InterfaceIndex -and
                [string]$accessState.tailscaleIPv4 -ceq [string]$audit.access.tailscale.ipv4
        }
        catch { $tailscaleAdapterBindingReady = $false }
    }
    if ($tailscaleAdapterBindingReady) { Add-Check 'tailscale-adapter-binding' 'PASS' 'The stored private address and interface alias resolve to the one live Up Tailscale adapter.' }
    else { Add-Check 'tailscale-adapter-binding' 'FAIL' 'Tailscale address-to-interface binding is stale, ambiguous, down, or unverified.' }
    if ($accessHardened -and $sshdConfigAuthorityReady -and (Test-Path -LiteralPath $sshdConfigPath)) {
        $sshdText = [IO.File]::ReadAllText($sshdConfigPath)
        $managedBlockReady = Test-SafeUnmanagedSshConfig -ConfigPathOnHost $sshdConfigPath
        $effectiveSshReady = Test-EffectiveSshConfiguration -Executable $script:SshdExe -ConfigPathOnHost $sshdConfigPath -Config $config -UserName ([string]$accessState.targetUser) -AuthorizedKeysPath ([string]$accessState.authorizedKeysPath) -SourceAddress ([string]$accessState.rebootProofSourceAddress) -LocalAddress ([string]$accessState.tailscaleIPv4)
        if ($managedBlockReady -and $effectiveSshReady) {
            Add-Check 'ssh-key-only' 'PASS' 'The non-replaceable ProgramData configuration authority, one managed SSH block, and effective target-user configuration are key-only and match the forwarding allowlist.'
        }
        else { Add-Check 'ssh-key-only' 'FAIL' 'Managed SSH state claims hardening, but its protected configuration authority or effective settings expose a conflicting Port, Include, Match, authentication, user, or forwarding directive.' }
    }
    else { Add-Check 'ssh-key-only' 'FAIL' 'A successful second-device proof and key-only SSH hardening are required.' }
    if ($authorizedKeysReady) { Add-Check 'ssh-key-allowlist' 'PASS' 'The machine-bound account, exact configured public-key set, and protected authorized-keys ACL match.' }
    else { Add-Check 'ssh-key-allowlist' 'FAIL' 'The account binding, public-key allowlist, or authorized-keys ACL does not exactly match the reviewed configuration.' }
    if ((Test-PrivilegedStateAcl -DirectoryPath $privilegedStateDir -RequiredFiles @($accessStatePath)) -and $sshdConfigAuthorityReady) { Add-Check 'access-state-integrity' 'PASS' 'Privileged access state and the OpenSSH configuration authority are non-reparse ProgramData paths writable only by SYSTEM and Administrators.' }
    else { Add-Check 'access-state-integrity' 'FAIL' 'Access state or OpenSSH configuration authority is absent, reparse-backed, or replaceable by an unprivileged account.' }
    $rebootProofReady = $false
    if ($accessState) {
        try {
            $stateProperties = @($accessState.PSObject.Properties.Name)
            if (@('rebootProofGeneratedUtc', 'rebootProofBootUtc', 'rebootProofHostEventRecordId', 'rebootProofHostEventUtc', 'rebootProofSourceAddress', 'proofMethod') | Where-Object { $_ -notin $stateProperties }) { throw 'Host-observed reboot proof fields are absent.' }
            if ([string]$accessState.proofMethod -cne 'v2-signed-host-observed' -or [long]$accessState.rebootProofHostEventRecordId -le 0) { throw 'Legacy or invalid reboot proof method.' }
            $currentBoot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime()
            $provedBoot = [DateTime]::Parse($accessState.rebootProofBootUtc).ToUniversalTime()
            $proofGenerated = [DateTime]::Parse($accessState.rebootProofGeneratedUtc).ToUniversalTime()
            $hostEventUtc = [DateTime]::Parse($accessState.rebootProofHostEventUtc).ToUniversalTime()
            $rebootProofReady = [math]::Abs(($currentBoot - $provedBoot).TotalSeconds) -lt 2 -and $proofGenerated -ge $currentBoot -and $hostEventUtc -ge $currentBoot -and $hostEventUtc -le $proofGenerated.AddMinutes(2)
        }
        catch { $rebootProofReady = $false }
    }
    if ($rebootProofReady) { Add-Check 'ssh-current-boot-proof' 'PASS' 'A fresh second-device key-only login proved unattended recovery for the current Windows boot.' }
    else { Add-Check 'ssh-current-boot-proof' 'FAIL' 'Strict 24/7 acceptance requires AccessAcceptRebootProof from the second laptop after the current boot.' }
    $sshdListenerExact = $false
    try {
        $sshdService = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
        $sshdListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object OwningProcess -eq [int]$sshdService.ProcessId)
        $sshdUdpEndpoints = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object OwningProcess -eq [int]$sshdService.ProcessId)
        $sshdListenerPorts = @($sshdListeners.LocalPort | Sort-Object -Unique)
        $reachableAddresses = @('0.0.0.0', '::', [string]$accessState.tailscaleIPv4, [string]$accessState.tailscaleIPv6)
        $sshdListenerExact = [int]$sshdService.ProcessId -gt 0 -and $sshdListenerPorts.Count -eq 1 -and
            [int]$sshdListenerPorts[0] -eq [int]$config.access.ssh.port -and
            @($sshdListeners | Where-Object LocalAddress -in $reachableAddresses).Count -gt 0 -and
            @($sshdListeners | Where-Object LocalAddress -notin $reachableAddresses).Count -eq 0 -and $sshdUdpEndpoints.Count -eq 0
    }
    catch { $sshdListenerExact = $false }
    if ($sshdListenerExact) { Add-Check 'ssh-listener-ownership' 'PASS' 'The sshd service owns a reachable listener on exactly the configured port and no other port.' }
    else { Add-Check 'ssh-listener-ownership' 'FAIL' 'Listener ownership and the absence of extra sshd ports are not proven.' }
    $sshdExe = $script:SshdExe
    $competingSshRules = @($audit.access.sensitiveFirewallRules | Where-Object {
        $_.Port -eq [int]$config.access.ssh.port -and $_.Enabled -eq 'True' -and $_.Action -in @('Allow', 'Block') -and
        $_.Name -notin @('EnvoyNode-SSH-Tailnet-IPv4', 'EnvoyNode-SSH-Tailnet-IPv6') -and
        (Test-FirewallRecordAppliesToProgram -Record $_ -ProgramPath $sshdExe -ServiceName 'sshd')
    })
    $managedSshExact = $false
    if ($audit.access.firewallInspectionComplete -and $accessState) {
        $expectedRules = @([pscustomobject]@{ Name = 'EnvoyNode-SSH-Tailnet-IPv4'; Local = [string]$accessState.tailscaleIPv4; Remote = '100.64.0.0/10' })
        if (-not [string]::IsNullOrWhiteSpace([string]$accessState.tailscaleIPv6)) {
            $expectedRules += [pscustomobject]@{ Name = 'EnvoyNode-SSH-Tailnet-IPv6'; Local = [string]$accessState.tailscaleIPv6; Remote = 'fd7a:115c:a1e0::/48' }
        }
        $managedRecords = @($audit.access.sensitiveFirewallRules | Where-Object {
            $_.Port -eq [int]$config.access.ssh.port -and $_.Name -in @('EnvoyNode-SSH-Tailnet-IPv4', 'EnvoyNode-SSH-Tailnet-IPv6')
        })
        $managedSshExact = $managedRecords.Count -eq $expectedRules.Count -and
            [string]$accessState.tailscaleIPv4 -eq [string]$audit.access.tailscale.ipv4 -and
            ([string]::IsNullOrWhiteSpace([string]$accessState.tailscaleIPv6) -or [string]$accessState.tailscaleIPv6 -eq [string]$audit.access.tailscale.ipv6)
        foreach ($expectedRule in $expectedRules) {
            $record = @($managedRecords | Where-Object Name -eq $expectedRule.Name)
            if ($record.Count -ne 1 -or -not (Test-ExactInboundAuditRule -Record $record[0] -Port ([int]$config.access.ssh.port) -ProgramPath $sshdExe -LocalAddress $expectedRule.Local -RemoteAddress $expectedRule.Remote -InterfaceAlias ([string]$accessState.tailscaleAdapter))) {
                $managedSshExact = $false
            }
        }
    }
    if ($managedSshExact -and $competingSshRules.Count -eq 0) { Add-Check 'ssh-tailnet-firewall' 'PASS' 'SSH firewall filters exactly match the current Tailscale addresses, adapter, program, port, and client ranges, with no competing allow/block rule.' }
    else { Add-Check 'ssh-tailnet-firewall' 'FAIL' 'The expected exclusive, reachable tailnet-only SSH firewall posture is not proven.' }
}

if ($config.access.desktop.enabled -and $config.access.desktop.provider -eq 'rdp' -and -not $audit.access.desktop.rdpHostSupported) {
    Add-Check 'desktop-edition' 'FAIL' 'Windows Home cannot host Microsoft RDP.'
}
elseif (-not $config.access.desktop.enabled) {
    $unexpectedDesktopListeners = @($audit.access.sensitiveListeners | Where-Object LocalPort -eq [int]$config.access.desktop.port)
    $unexpectedDesktopRules = @($audit.access.sensitiveFirewallRules | Where-Object {
        $_.Port -eq [int]$config.access.desktop.port -and $_.Enabled -eq 'True' -and $_.Action -eq 'Allow'
    })
    $disabledServiceReady = $false
    try {
        $rustDeskServicesWhenDisabled = @(Get-CimInstance Win32_Service -Filter "Name='RustDesk'" -ErrorAction Stop)
        $disabledServiceReady = $rustDeskServicesWhenDisabled.Count -eq 0 -or
            ($rustDeskServicesWhenDisabled.Count -eq 1 -and [string]$rustDeskServicesWhenDisabled[0].State -eq 'Stopped' -and [string]$rustDeskServicesWhenDisabled[0].StartMode -eq 'Disabled')
    }
    catch { $disabledServiceReady = $false }
    if ($audit.access.listenerInspectionComplete -and $unexpectedDesktopListeners.Count -eq 0 -and $disabledServiceReady -and $audit.access.firewallInspectionComplete -and $unexpectedDesktopRules.Count -eq 0) {
        Add-Check 'desktop-disabled' 'PASS' 'Optional GUI control is absent or Stopped/Disabled, with no listener or enabled allow rule on its managed port.'
    }
    else { Add-Check 'desktop-disabled' 'FAIL' 'Desktop is disabled in configuration, but the service is not absent or Stopped/Disabled, a managed-port listener/allow rule exists, or inspection is incomplete.' }
}
elseif ($config.access.desktop.provider -eq 'rustdesk-direct') {
    $desktopStatePath = Join-Path $env:ProgramData 'EnvoyNode\state\desktop-current.json'
    $desktopStateReady = $false
    $desktopStateBound = $false
    $desktopStateProtected = Test-PrivilegedStateAcl -DirectoryPath (Split-Path $desktopStatePath -Parent) -RequiredFiles @($accessStatePath, $desktopStatePath)
    if ($desktopStateProtected) { Add-Check 'desktop-state-integrity' 'PASS' 'Desktop lifecycle state and its parent directories have exact protected ACLs and owners.' }
    else { Add-Check 'desktop-state-integrity' 'FAIL' 'Desktop lifecycle state is absent, replaceable, reparse-backed, or not exactly protected.' }
    if ($desktopStateProtected) {
        try {
            $desktopState = Get-Content -LiteralPath $desktopStatePath -Raw | ConvertFrom-Json
            $desktopProperties = @($desktopState.PSObject.Properties.Name)
            if (@('executable', 'executableSha256', 'signer', 'serviceAccount', 'serviceAccountSid', 'serviceCommandMode', 'serverCommandMode') | Where-Object { $_ -notin $desktopProperties }) { throw 'Desktop protected service identity fields are absent.' }
            $desktopStateBound = $desktopState.machineFingerprint -eq $audit.machineFingerprint -and $desktopState.status -in @('enable-in-progress', 'enabled-awaiting-reboot-proof', 'enabled-tailnet-only') -and $desktopState.whitelistAcknowledged -and $desktopState.publicEgressBlocked -and
                [string]$desktopState.serviceAccountSid -in @('S-1-5-18', 'S-1-5-19') -and [string]$desktopState.serviceCommandMode -ceq '--service' -and [string]$desktopState.serverCommandMode -ceq '--server' -and
                [string]$desktopState.tailscaleIPv4 -eq [string]$audit.access.tailscale.ipv4 -and
                ([string]::IsNullOrWhiteSpace([string]$desktopState.tailscaleIPv6) -or [string]$desktopState.tailscaleIPv6 -eq [string]$audit.access.tailscale.ipv6)
            if ($desktopState.status -eq 'enabled-tailnet-only') {
                if (@('enabledBootUtc', 'desktopProofBootUtc', 'desktopProofAcceptedUtc', 'postRebootClientTestAcknowledged') | Where-Object { $_ -notin $desktopProperties }) { throw 'Desktop reboot proof fields are absent.' }
                $desktopCurrentBoot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime()
                $desktopEnabledBoot = [DateTime]::Parse([string]$desktopState.enabledBootUtc).ToUniversalTime()
                $desktopProvedBoot = [DateTime]::Parse([string]$desktopState.desktopProofBootUtc).ToUniversalTime()
                $desktopStateReady = $desktopStateBound -and $desktopState.postRebootClientTestAcknowledged -and $desktopCurrentBoot -gt $desktopEnabledBoot -and [math]::Abs(($desktopCurrentBoot - $desktopProvedBoot).TotalSeconds) -lt 2
            }
        }
        catch { }
    }
    $rustDeskService = Get-Service RustDesk -ErrorAction SilentlyContinue
    $desktopRulesReady = $false
    $desktopListenerReady = $false
    $verifiedDesktopListenerIdentity = $null
    $desktopEgressConflictFree = $false
    $desktopInboundConflictFree = $false
    $desktopServiceIdentity = $null
    try {
        $desktopServiceIdentity = Test-RustDeskServiceIdentity -StateObject $desktopState
        if (-not $desktopServiceIdentity) { throw 'RustDesk protected binary or root service identity is not exact.' }
        $rustDeskExe = [string]$desktopServiceIdentity.Executable
        $desktopHashMatches = (Get-FileHash -LiteralPath $rustDeskExe -Algorithm SHA256).Hash.ToLowerInvariant() -eq [string]$desktopState.executableSha256
        $competingDesktopInboundBlocks = @($audit.access.sensitiveFirewallRules | Where-Object {
            $_.Port -eq [int]$config.access.desktop.port -and $_.Enabled -eq 'True' -and $_.Action -eq 'Block' -and
            (Test-FirewallRecordAppliesToProgram -Record $_ -ProgramPath $rustDeskExe -ServiceName 'RustDesk')
        })
        $desktopInboundConflictFree = $competingDesktopInboundBlocks.Count -eq 0
        $unexpectedDesktopOutboundBlocks = @($audit.access.outboundBlockRules | Where-Object {
            $_.Name -notin @('EnvoyNode-RustDesk-Block-Public-IPv4', 'EnvoyNode-RustDesk-Block-Public-IPv6') -and
            (Test-FirewallRecordAppliesToProgram -Record $_ -ProgramPath $rustDeskExe -ServiceName 'RustDesk')
        })
        $desktopEgressConflictFree = $audit.access.outboundAllowBypassInspectionComplete -and @($audit.access.outboundAllowBypassRules).Count -eq 0 -and
            $audit.access.outboundBlockInspectionComplete -and $unexpectedDesktopOutboundBlocks.Count -eq 0
        $inbound4 = Get-LiveFirewallRuleSnapshot -Name 'EnvoyNode-RustDesk-Tailnet-IPv4'
        $inbound4Ready = Test-ExactLiveInboundRule -Snapshot $inbound4 -Port ([int]$config.access.desktop.port) -ProgramPath $rustDeskExe -LocalAddress ([string]$desktopState.tailscaleIPv4) -RemoteAddress '100.64.0.0/10' -InterfaceAlias ([string]$desktopState.tailscaleAdapter)
        $inbound6Ready = $true
        if (-not [string]::IsNullOrWhiteSpace([string]$desktopState.tailscaleIPv6)) {
            $inbound6 = Get-LiveFirewallRuleSnapshot -Name 'EnvoyNode-RustDesk-Tailnet-IPv6'
            $inbound6Ready = Test-ExactLiveInboundRule -Snapshot $inbound6 -Port ([int]$config.access.desktop.port) -ProgramPath $rustDeskExe -LocalAddress ([string]$desktopState.tailscaleIPv6) -RemoteAddress 'fd7a:115c:a1e0::/48' -InterfaceAlias ([string]$desktopState.tailscaleAdapter)
        }
        else {
            $unexpectedIpv6Rule = @(Get-NetFirewallRule -Name 'EnvoyNode-RustDesk-Tailnet-IPv6' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True')
            $inbound6Ready = $unexpectedIpv6Rule.Count -eq 0
        }
        $outbound4 = Get-LiveFirewallRuleSnapshot -Name 'EnvoyNode-RustDesk-Block-Public-IPv4'
        $outbound6 = Get-LiveFirewallRuleSnapshot -Name 'EnvoyNode-RustDesk-Block-Public-IPv6'
        $outbound4Ready = Test-ExactLiveOutboundBlockRule -Snapshot $outbound4 -ProgramPath $rustDeskExe -RemoteAddresses @('0.0.0.0-100.63.255.255', '100.128.0.0-126.255.255.255', '128.0.0.0-255.255.255.255')
        $outbound6Ready = Test-ExactLiveOutboundBlockRule -Snapshot $outbound6 -ProgramPath $rustDeskExe -RemoteAddresses @('::2-fd7a:115c:a1df:ffff:ffff:ffff:ffff:ffff', 'fd7a:115c:a1e1::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
        $desktopRulesReady = $desktopHashMatches -and $desktopServiceIdentity -and $inbound4Ready -and $inbound6Ready -and $outbound4Ready -and $outbound6Ready -and $desktopInboundConflictFree -and $desktopEgressConflictFree
    }
    catch { $desktopRulesReady = $false }
    try {
        $runningDesktopIdentity = Test-RustDeskServiceIdentity -StateObject $desktopState -RequireRunning
        $allowedListenerAddresses = @('0.0.0.0', '::', [string]$desktopState.tailscaleIPv4, [string]$desktopState.tailscaleIPv6)
        if ($runningDesktopIdentity) {
            $verifiedDesktopListenerIdentity = Test-RustDeskDirectListenerIdentity -ServiceIdentity $runningDesktopIdentity -Port ([int]$config.access.desktop.port) -AllowedLocalAddresses $allowedListenerAddresses
        }
        $desktopListenerReady = [bool]$verifiedDesktopListenerIdentity
    }
    catch { $desktopListenerReady = $false }
    if ($desktopEgressConflictFree -and $desktopInboundConflictFree) { Add-Check 'desktop-firewall-conflicts' 'PASS' 'No authenticated outbound bypass or competing inbound/outbound block can defeat the reviewed RustDesk path.' }
    else { Add-Check 'desktop-firewall-conflicts' 'FAIL' 'A firewall allow-bypass, competing block, or incomplete conflict scan can defeat or bypass the reviewed RustDesk path.' }
    if ($desktopStateBound -and $desktopRulesReady) { Add-Check 'desktop-firewall-exact' 'PASS' 'The protected RustDesk tree, built-in service account/commands, and every effective private-ingress/public-egress firewall filter are exact.' }
    else { Add-Check 'desktop-firewall-exact' 'FAIL' 'RustDesk binary-tree/service authority or exact fully enforced firewall posture is not proven.' }
    if ($desktopStateBound -and $rustDeskService -and $rustDeskService.Status -eq 'Running' -and $rustDeskService.StartType -eq 'Automatic' -and $desktopRulesReady -and $desktopListenerReady) { Add-Check 'desktop-live-posture' 'PASS' 'The protected RustDesk --service root and --server child own exactly the reviewed TCP listener; the managed port has no UDP endpoint.' }
    else { Add-Check 'desktop-live-posture' 'FAIL' 'Same-boot RustDesk root/child process, listener, binary-tree, account, or firewall posture is not exact.' }
    if ($desktopStateReady -and $rustDeskService -and $rustDeskService.Status -eq 'Running' -and $rustDeskService.StartType -eq 'Automatic' -and $desktopRulesReady -and $desktopListenerReady) {
        Add-Check 'desktop-tailnet-only' 'PASS' 'RustDesk executable, owned listener, exact private ingress filters, and exact public-egress blocks are active.'
    }
    else { Add-Check 'desktop-tailnet-only' 'FAIL' 'Enabled desktop control is not fully proven tailnet-only and reboot-safe.' }
}

$allowedInboundRuleNames = New-Object System.Collections.Generic.List[string]
if ($config.access.ssh.enabled) {
    $allowedInboundRuleNames.Add('EnvoyNode-SSH-Tailnet-IPv4')
    $allowedInboundRuleNames.Add('EnvoyNode-SSH-Tailnet-IPv6')
}
if ($config.access.desktop.enabled -and $config.access.desktop.provider -eq 'rustdesk-direct') {
    $allowedInboundRuleNames.Add('EnvoyNode-RustDesk-Tailnet-IPv4')
    $allowedInboundRuleNames.Add('EnvoyNode-RustDesk-Tailnet-IPv6')
}
$unexpectedProtectedRules = @($audit.access.sensitiveFirewallRules | Where-Object {
    $_.Enabled -eq 'True' -and $_.Action -eq 'Allow' -and $_.Name -notin @($allowedInboundRuleNames)
})
$expectedListenerOwners = @{}
if ($config.access.ssh.enabled) {
    try {
        $serviceRecord = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
        if ([int]$serviceRecord.ProcessId -gt 0) { $expectedListenerOwners["TCP:$([int]$config.access.ssh.port):$([int]$serviceRecord.ProcessId)"] = $true }
    }
    catch { }
}
if ($config.access.desktop.enabled -and $config.access.desktop.provider -eq 'rustdesk-direct') {
    if ($verifiedDesktopListenerIdentity -and [int]$verifiedDesktopListenerIdentity.Listener.OwningProcess -eq [int]$verifiedDesktopListenerIdentity.ServerProcess.ProcessId) {
        $expectedListenerOwners["TCP:$([int]$config.access.desktop.port):$([int]$verifiedDesktopListenerIdentity.ServerProcess.ProcessId)"] = $true
    }
}
$unexpectedProtectedListeners = @($audit.access.sensitiveListeners | Where-Object {
    $key = "$([string]$_.Protocol):$([int]$_.LocalPort):$([int]$_.OwningProcess)"
    -not $expectedListenerOwners.ContainsKey($key)
})
$globalProtectedExposureReady = $audit.access.firewallInspectionComplete -and $audit.access.listenerInspectionComplete -and
    $unexpectedProtectedRules.Count -eq 0 -and $unexpectedProtectedListeners.Count -eq 0 -and -not $audit.access.desktop.rdpEnabled
if ($globalProtectedExposureReady) { Add-Check 'global-managed-port-exposure' 'PASS' 'Every TCP/UDP listener and enabled allow rule on protected ports belongs to an expected managed service, and RDP remains off.' }
else { Add-Check 'global-managed-port-exposure' 'FAIL' 'An unexpected TCP/UDP listener, enabled allow rule, RDP state, or incomplete inspection exists on the protected remote-access ports.' }

if ($audit.compute.wslInstalled) { Add-Check 'wsl-present' 'PASS' 'WSL2 is available.' }
else { Add-Check 'wsl-present' 'FAIL' 'WSL is not available.' }

$distroPresent = @($audit.compute.distributions) -contains $config.compute.distribution
$runningInventoryComplete = [bool]$audit.compute.runningDistributionInspectionComplete
$distroRunning = [bool]($runningInventoryComplete -and @($audit.compute.runningDistributions) -contains $config.compute.distribution)
if (-not $config.compute.enabled) {
    Add-Check 'compute-disabled' 'PASS' 'The optional compute layer is disabled in configuration.'
}
elseif ($distroPresent) {
    Add-Check 'compute-distro' 'PASS' "The $($config.compute.distribution) distribution exists for the current Windows user."
    if (-not $runningInventoryComplete -or -not $distroRunning) {
        try {
            $offlineProof = & (Join-Path $PSScriptRoot 'Test-EnvoyCompute.ps1') -ConfigPath $ConfigPath -PassThru -NoReport -OfflineOnly
            if ($offlineProof.passed) { Add-Check 'compute-offline-binding' 'PASS' 'Protected compute state exactly matches this machine, owner, ready lifecycle, and live version-2 WSL registration without launching the distribution.' }
            else { Add-Check 'compute-offline-binding' 'FAIL' 'The non-launching compute ownership and registration proof failed.' }
        }
        catch { Add-Check 'compute-offline-binding' 'FAIL' "The non-launching compute ownership and registration proof failed: $($_.Exception.Message)" }
        if (-not $runningInventoryComplete) {
            Add-Check 'compute-running-inventory' 'FAIL' 'WSL running-state inventory was inconclusive. General Verify did not launch the distribution or attempt live proof.'
            Add-Check 'dedicated-compute-engine' 'WARN' 'Live Linux marker and Docker posture proof were skipped because running state was not conclusive.'
        }
        else {
            Add-Check 'compute-running-inventory' 'PASS' 'The on-demand compute distribution is conclusively stopped.'
            Add-Check 'dedicated-compute-engine' 'WARN' 'General Verify left the on-demand distribution stopped. Offline ownership binding passed, but live Linux marker and Docker proof require deliberate ComputeVerify.'
        }
    }
    else {
        Add-Check 'compute-running-inventory' 'PASS' 'The compute distribution was already running before General Verify.'
        try {
            $computeProof = & (Join-Path $PSScriptRoot 'Test-EnvoyCompute.ps1') -ConfigPath $ConfigPath -PassThru -NoReport -SkipSmoke -RequireAlreadyRunning
            if ($computeProof.passed) { Add-Check 'dedicated-compute-engine' 'PASS' "The already-running dedicated WSL Docker engine passed read-only posture checks (server $($computeProof.dockerServerVersion)); no transient container was created." }
            else { Add-Check 'dedicated-compute-engine' 'FAIL' 'The running dedicated WSL Docker engine posture proof failed.' }
        }
        catch { Add-Check 'dedicated-compute-engine' 'FAIL' "The running dedicated WSL Docker engine could not be verified: $($_.Exception.Message)" }
    }
}
else { Add-Check 'compute-distro' 'FAIL' 'Compute is enabled in configuration, but the dedicated distribution has not been created.' }

if ($audit.compute.dockerRunning) { Add-Check 'host-sandbox-runtime' 'PASS' 'The separate host Docker engine remains available for the project-owned sandbox smoke test.' }
else { Add-Check 'host-sandbox-runtime' 'WARN' 'The optional host sandbox runtime is not running; this does not substitute for the dedicated compute engine.' }

if ($config.compute.gpu.activate) {
    Add-Check 'gpu-proof' 'FAIL' 'GPU activation is requested, but this verifier requires a successful ROCm gfx1151 proof report that is not yet present.'
}
else {
    Add-Check 'gpu-deferred' 'PASS' 'GPU activation remains a separate, deliberate phase.'
}

if ($audit.security.defender -and $audit.security.defender.RealTimeProtectionEnabled) { Add-Check 'defender' 'PASS' 'Microsoft Defender real-time protection is enabled.' }
else { Add-Check 'defender' 'FAIL' 'Defender real-time protection must be verified for acceptance.' }
if ($audit.security.uacInspectionComplete -and $audit.security.uacEnabled) { Add-Check 'uac' 'PASS' 'User Account Control is enabled.' }
else { Add-Check 'uac' 'FAIL' 'User Account Control must be verified enabled for acceptance.' }
if ($audit.security.secureBootInspectionComplete -and $audit.security.secureBootEnabled) { Add-Check 'secure-boot' 'PASS' 'Secure Boot is enabled.' }
else { Add-Check 'secure-boot' 'FAIL' 'Secure Boot must be verified enabled for acceptance.' }
if (-not $audit.host.pendingReboot) { Add-Check 'pending-reboot-clear' 'PASS' 'Windows does not report a pending servicing or update reboot.' }
else { Add-Check 'pending-reboot-clear' 'FAIL' 'Complete the pending Windows reboot and repeat current-boot access proof before acceptance.' }
if ($audit.security.systemDriveEncryption.Protection -match 'On') { Add-Check 'drive-encryption' 'PASS' 'System-drive encryption protection is on.' }
else { Add-Check 'drive-encryption' 'FAIL' 'System-drive encryption and recovery-key access must be verified before unattended acceptance.' }

if ($audit.security.pluggedInSleepSeconds -eq 0) { Add-Check 'ac-sleep' 'PASS' 'Plugged-in sleep is disabled.' }
else { Add-Check 'ac-sleep' 'FAIL' 'Plugged-in sleep may interrupt remote availability.' }
if ($audit.security.pluggedInHibernateSeconds -eq 0) { Add-Check 'ac-hibernate' 'PASS' 'Plugged-in idle hibernation is disabled.' }
else { Add-Check 'ac-hibernate' 'FAIL' 'Plugged-in hibernation may interrupt remote availability.' }
if ($audit.security.pluggedInLidAction -eq 0) { Add-Check 'ac-lid' 'PASS' 'Closing the lid while plugged in does not suspend the node.' }
else { Add-Check 'ac-lid' 'FAIL' 'The plugged-in lid action may interrupt remote availability.' }

$computeAvailability = if ($config.compute.PSObject.Properties.Name -contains 'availability') { [string]$config.compute.availability } else { 'on-demand' }
if ($computeAvailability -eq 'on-demand') { Add-Check 'compute-lifecycle' 'PASS' 'WSL compute is explicitly on-demand; SSH can start it after reboot. This is not 24/7 pre-login inference.' }
else { Add-Check 'compute-lifecycle' 'FAIL' 'Always-on WSL inference is not implemented or claimed by this pilot; use the future native-Linux node.' }

$failCount = @($checks | Where-Object status -eq 'FAIL').Count
$warnCount = @($checks | Where-Object status -eq 'WARN').Count
$report = [pscustomobject][ordered]@{
    reportVersion = 1
    generatedUtc = [DateTime]::UtcNow.ToString('o')
    mode = 'strict-acceptance'
    acceptanceReady = ($failCount -eq 0)
    passed = ($failCount -eq 0)
    failCount = $failCount
    warningCount = $warnCount
    checks = $checks.ToArray()
}

if (-not $NoReport -and [string]::IsNullOrWhiteSpace($OutputPath)) {
    $projectRoot = Split-Path $PSScriptRoot -Parent
    $OutputPath = Join-Path $projectRoot 'reports\verify-latest.json'
}
if (-not $NoReport) {
    $directory = Split-Path $OutputPath -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
}

if ($PassThru) { return $report }

if ($Json) { $report | ConvertTo-Json -Depth 8 }
else {
    foreach ($check in $checks) { Write-Output "[$($check.status)] $($check.id): $($check.message)" }
    $reportLocation = if ($NoReport) { 'not written' } else { $OutputPath }
    $readiness = if ($failCount -eq 0) { 'READY' } else { 'NOT READY' }
    Write-Output "Strict acceptance: $readiness; $failCount failure(s), $warnCount warning(s). Report: $reportLocation"
}

if ($failCount -gt 0) { exit 1 }
exit 0
