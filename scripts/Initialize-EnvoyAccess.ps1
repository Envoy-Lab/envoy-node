[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Preview', 'Prepare', 'Enable', 'Harden', 'RebootProof', 'Disable')]
    [string]$Stage,

    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [string]$PublicKeyPath,
    [string]$TargetUser,
    [string]$ClientProofPath,
    [string]$ApprovedPlanHash,
    [string]$ApprovedPlanPath,
    [switch]$Apply,
    [switch]$AcknowledgeAdministratorTarget,
    [switch]$AcknowledgeTailnetControls
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:WindowsSystemDirectory = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { Join-Path $env:WINDIR 'Sysnative' } else { Join-Path $env:WINDIR 'System32' }
$script:IcaclsExe = Join-Path $script:WindowsSystemDirectory 'icacls.exe'
$script:SshKeygenExe = Join-Path $script:WindowsSystemDirectory 'OpenSSH\ssh-keygen.exe'

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-NoReparsePathChain {
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$RequireLeaf, [switch]$RequireDirectoryLeaf, [switch]$RequireFileLeaf)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root)) { throw "Path has no trusted filesystem root: $Path" }
    $current = $root
    $relative = $fullPath.Substring($root.Length)
    foreach ($segment in @($relative -split '[\\/]' | Where-Object { $_ })) {
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) { break }
        $item = Get-Item -LiteralPath $current -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing reparse-backed privileged path: $current" }
    }
    if ($RequireLeaf -and -not (Test-Path -LiteralPath $fullPath)) { throw "Required path does not exist: $fullPath" }
    if ($RequireDirectoryLeaf -and -not (Test-Path -LiteralPath $fullPath -PathType Container)) { throw "Required directory does not exist: $fullPath" }
    if ($RequireFileLeaf -and -not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { throw "Required file does not exist: $fullPath" }
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
    if ($hadContent -and -not $AllowRepairWithContent -and -not (Test-ExactPrivilegedDirectoryAcl -Path $Path)) {
        throw 'Privileged state already contains data but its ACL is not the exact SYSTEM/Administrators policy. Refusing to adopt or repair potentially forged lifecycle state.'
    }
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

function Protect-SshConfigurationDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    $expectedPath = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'ssh'))
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath -ine $expectedPath) { throw "Refusing to protect a noncanonical OpenSSH configuration directory: $fullPath" }
    Assert-NoReparsePathChain -Path $env:ProgramData -RequireDirectoryLeaf
    if (Test-Path -LiteralPath $fullPath) {
        Assert-NoReparsePathChain -Path $fullPath -RequireDirectoryLeaf
        $hasContent = @(Get-ChildItem -LiteralPath $fullPath -Force -ErrorAction Stop).Count -gt 0
        if ($hasContent -and -not (Test-ExactPrivilegedDirectoryAcl -Path $fullPath)) {
            throw 'The existing OpenSSH configuration directory contains data but is not the exact protected SYSTEM/Administrators tree. Refusing to adopt or repair replaceable SSH authority.'
        }
    }
    else { [IO.Directory]::CreateDirectory($fullPath) | Out-Null }
    Assert-NoReparsePathChain -Path $fullPath -RequireDirectoryLeaf
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $administrators = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl.SetOwner($administrators)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($system, $administrators)) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)))
    }
    Set-Acl -LiteralPath $fullPath -AclObject $acl
    if (-not (Test-ExactPrivilegedDirectoryAcl -Path $fullPath)) { throw 'Could not establish the exact protected OpenSSH configuration-directory ACL.' }
}

function Assert-SshConfigurationAuthority {
    param([Parameter(Mandatory = $true)][string]$DirectoryPath, [Parameter(Mandatory = $true)][string]$ConfigPath)
    $expectedDirectory = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'ssh'))
    $expectedConfig = [IO.Path]::GetFullPath((Join-Path $expectedDirectory 'sshd_config'))
    if ([IO.Path]::GetFullPath($DirectoryPath) -ine $expectedDirectory -or [IO.Path]::GetFullPath($ConfigPath) -ine $expectedConfig) { throw 'OpenSSH configuration authority is not at the canonical ProgramData path.' }
    Assert-NoReparsePathChain -Path $expectedDirectory -RequireDirectoryLeaf
    Assert-NoReparsePathChain -Path $expectedConfig -RequireFileLeaf
    if (-not (Test-ExactPrivilegedDirectoryAcl -Path $expectedDirectory) -or -not (Test-ExactPrivilegedFileAcl -Path $expectedConfig)) {
        throw 'The OpenSSH configuration directory or sshd_config ACL/owner is not the exact protected SYSTEM/Administrators policy.'
    }
}

function Protect-SshConfigurationFile {
    param([Parameter(Mandatory = $true)][string]$DirectoryPath, [Parameter(Mandatory = $true)][string]$ConfigPath)
    $expectedDirectory = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'ssh'))
    if ([IO.Path]::GetFullPath($DirectoryPath) -ine $expectedDirectory -or -not (Test-ExactPrivilegedDirectoryAcl -Path $expectedDirectory)) { throw 'The canonical OpenSSH configuration directory is not protected.' }
    Assert-NoReparsePathChain -Path $ConfigPath -RequireFileLeaf
    Protect-EnvoyStateFile -Path $ConfigPath
    Assert-SshConfigurationAuthority -DirectoryPath $DirectoryPath -ConfigPath $ConfigPath
}

function Set-ExactStandardSshDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$TargetSid)
    Assert-NoReparsePathChain -Path $Path -RequireDirectoryLeaf
    $target = New-Object Security.Principal.SecurityIdentifier($TargetSid)
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $administrators = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($target)
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($target, $system, $administrators)) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-ExactStandardSshDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$TargetSid)
    Assert-NoReparsePathChain -Path $Path -RequireDirectoryLeaf
    $acl = Get-Acl -LiteralPath $Path
    try { $ownerSid = (New-Object Security.Principal.NTAccount($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { throw 'The standard-account .ssh directory owner could not be resolved.' }
    if ($ownerSid -ne $TargetSid -or -not $acl.AreAccessRulesProtected) { throw 'The standard-account .ssh directory owner or inheritance protection is not exact.' }
    $allowedSids = @($TargetSid, 'S-1-5-18', 'S-1-5-32-544')
    $rules = @($acl.Access)
    if ($rules.Count -ne $allowedSids.Count) { throw 'The standard-account .ssh directory does not have exactly three access rules.' }
    $seen = New-Object System.Collections.Generic.HashSet[string]
    $expectedInheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($rule in $rules) {
        try { $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
        catch { throw 'A standard-account .ssh directory ACL identity could not be resolved.' }
        if ($rule.IsInherited -or $sid -notin $allowedSids -or [string]$rule.AccessControlType -ne 'Allow' -or
            [int]$rule.FileSystemRights -ne [int][Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne $expectedInheritance -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw 'The standard-account .ssh directory ACL is not the exact trusted-principal policy.'
        }
        $null = $seen.Add($sid)
    }
    if ($seen.Count -ne $allowedSids.Count -or @($allowedSids | Where-Object { -not $seen.Contains($_) }).Count -gt 0) { throw 'The standard-account .ssh directory is missing a required trusted principal.' }
}

function Assert-ExactAuthorizedKeysAcl {
    param($StateObject)
    $path = [string]$StateObject.authorizedKeysPath
    Assert-NoReparsePathChain -Path (Split-Path $path -Parent) -RequireDirectoryLeaf
    Assert-NoReparsePathChain -Path $path -RequireFileLeaf
    if (-not [bool]$StateObject.targetIsAdministrator) { Assert-ExactStandardSshDirectoryAcl -Path (Split-Path $path -Parent) -TargetSid ([string]$StateObject.targetSid) }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'The authorized-keys file is missing.' }
    if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'The authorized-keys file is a reparse point.' }
    $allowedSids = if ([bool]$StateObject.targetIsAdministrator) { @('S-1-5-18', 'S-1-5-32-544') } else { @('S-1-5-18', 'S-1-5-32-544', [string]$StateObject.targetSid) }
    $acl = Get-Acl -LiteralPath $path
    if (-not $acl.AreAccessRulesProtected -or @($acl.Access).Count -ne $allowedSids.Count) { throw 'The authorized-keys ACL is not the exact protected trusted-principal policy.' }
    $seen = New-Object System.Collections.Generic.HashSet[string]
    foreach ($rule in @($acl.Access)) {
        try { $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
        catch { throw 'An authorized-keys ACL identity could not be resolved.' }
        if ($rule.IsInherited -or $sid -notin $allowedSids -or [string]$rule.AccessControlType -ne 'Allow' -or
            [int]$rule.FileSystemRights -ne [int][Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw 'The authorized-keys ACL contains an unexpected identity, access type, rights set, or inheritance flag.'
        }
        $null = $seen.Add($sid)
    }
    if ($seen.Count -ne $allowedSids.Count -or @($allowedSids | Where-Object { -not $seen.Contains($_) }).Count -gt 0) { throw 'The authorized-keys ACL does not contain exactly the required principals.' }
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
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Path, [int]$Depth = 8)
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

function Copy-EnvoyStateFile {
    param([Parameter(Mandatory = $true)][string]$Source, [Parameter(Mandatory = $true)][string]$Destination, [switch]$Force)
    Copy-Item -LiteralPath $Source -Destination $Destination -Force:$Force
    Protect-EnvoyStateFile -Path $Destination
}

function Assert-AccessStateBinding {
    param($StateObject, [string]$MachineFingerprint, [string]$ExpectedUser = $null, [string]$ExpectedSid = $null, [int]$ExpectedPort = 0, [int]$ExpectedAdministrator = -1)
    if (-not $StateObject) { throw 'Access state is missing.' }
    $properties = @($StateObject.PSObject.Properties.Name)
    if (@('schemaVersion', 'machineFingerprint', 'targetUser', 'targetSid', 'targetIsAdministrator', 'sshPort', 'status') | Where-Object { $_ -notin $properties }) { throw 'Access state is missing required binding fields.' }
    if ($StateObject.schemaVersion -ne 1) { throw 'Access state schema is unsupported.' }
    if ($StateObject.machineFingerprint -ne $MachineFingerprint) { throw 'Access state belongs to a different Windows installation; refusing to control local services.' }
    if ([int]$StateObject.sshPort -lt 1 -or [int]$StateObject.sshPort -gt 65535) { throw 'Access state contains an invalid managed SSH port.' }
    if ($ExpectedUser -and $StateObject.targetUser -ine $ExpectedUser) { throw 'Access state target user does not match.' }
    if ($ExpectedSid -and $StateObject.targetSid -ne $ExpectedSid) { throw 'Access state target SID does not match the current local account.' }
    if ($ExpectedPort -gt 0 -and [int]$StateObject.sshPort -ne $ExpectedPort) { throw 'Access state SSH port does not match the reviewed configuration.' }
    if ($ExpectedAdministrator -ge 0 -and [bool]$StateObject.targetIsAdministrator -ne [bool]$ExpectedAdministrator) { throw 'Access state administrator status no longer matches the target account.' }
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

function Assert-SshAccessFailedClosed {
    param([string[]]$OwnedRuleNames, [int]$Port)
    $service = Get-Service sshd -ErrorAction Stop
    Assert-SshdServiceIdentity -ExpectedExecutable $sshdExe | Out-Null
    $serviceCim = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
    if ($service.Status -ne 'Stopped' -or [string]$serviceCim.StartMode -ne 'Disabled') {
        throw "sshd is status '$($service.Status)' with startup '$($serviceCim.StartMode)', not Stopped/Disabled."
    }
    $protectedNames = @($OwnedRuleNames + @('OpenSSH-Server-In-TCP'))
    $activeStoreRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
    $enabledProtectedRules = @($activeStoreRules | Where-Object { $_.Name -in $protectedNames -and [string]$_.Enabled -eq 'True' })
    if ($enabledProtectedRules.Count -gt 0) { throw 'An EnvoyNode or default OpenSSH inbound firewall rule remains enabled.' }
    $tcpListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { [int]$_.LocalPort -eq $Port })
    $udpListeners = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { [int]$_.LocalPort -eq $Port })
    if ($tcpListeners.Count -gt 0 -or $udpListeners.Count -gt 0) { throw "A TCP or UDP listener remains on the managed SSH port $Port." }
}

function Restore-SshdServiceState {
    param([bool]$WasRunning, [string]$StartMode)
    Stop-Service sshd -Force -ErrorAction SilentlyContinue
    switch ($StartMode) {
        'Auto' { Set-Service sshd -StartupType Automatic }
        'Automatic' { Set-Service sshd -StartupType Automatic }
        'Disabled' { Set-Service sshd -StartupType Disabled }
        default { Set-Service sshd -StartupType Manual }
    }
    if ($WasRunning) { Start-Service sshd }
}

function Set-StateProperty {
    param($StateObject, [string]$Name, $Value)
    if ($StateObject.PSObject.Properties.Name -contains $Name) { $StateObject.$Name = $Value }
    else { $StateObject | Add-Member -NotePropertyName $Name -NotePropertyValue $Value }
}

function Assert-VerificationChecks {
    param($Verification, [string[]]$RequiredIds)
    $failed = @($Verification.checks | Where-Object { $_.id -in $RequiredIds -and $_.status -ne 'PASS' })
    $missing = @($RequiredIds | Where-Object { $_ -notin @($Verification.checks.id) })
    if ($failed.Count -gt 0 -or $missing.Count -gt 0) {
        $details = @($failed | ForEach-Object { "$($_.id): $($_.message)" }) + @($missing | ForEach-Object { "$_`: missing" })
        throw 'Required exact live verification failed: ' + ($details -join '; ')
    }
}

function New-ClientProofChallenge {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) }
    finally { $rng.Dispose() }
    return ([BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}

function Get-Sha256FingerprintToken {
    param([string]$Fingerprint)
    if ($Fingerprint -notmatch '(SHA256:[A-Za-z0-9+/]+)') { throw 'An SSH fingerprint does not contain a valid SHA256 token.' }
    return $Matches[1]
}

function Test-TailscaleSourceAddress {
    param([string]$Address)
    try { $ip = [Net.IPAddress]::Parse($Address) }
    catch { return $false }
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and $ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
    $bytes = $ip.GetAddressBytes()
    if ($bytes.Count -eq 4) { return [bool]($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) }
    if ($bytes.Count -eq 16) { return [bool]($bytes[0] -eq 0xfd -and $bytes[1] -eq 0x7a -and $bytes[2] -eq 0x11 -and $bytes[3] -eq 0x5c -and $bytes[4] -eq 0xa1 -and $bytes[5] -eq 0xe0) }
    return $false
}

function Get-CanonicalIpAddress {
    param([string]$Address)
    try { $ip = [Net.IPAddress]::Parse($Address) }
    catch { throw "Invalid IP address in signed SSH proof or protected state: $Address" }
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and $ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
    return $ip
}

function Get-HostObservedSshAuthentication {
    param(
        [string]$UserName,
        [string]$SourceAddress,
        [string]$FingerprintToken,
        [DateTime]$NotBeforeUtc,
        [DateTime]$NotAfterUtc
    )
    try {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName = 'OpenSSH/Operational'
            StartTime = $NotBeforeUtc.ToLocalTime()
            EndTime = $NotAfterUtc.ToLocalTime()
        } -ErrorAction Stop)
    }
    catch { throw "The host OpenSSH Operational log could not be read; independent public-key authentication proof is required. $($_.Exception.Message)" }
    $userPattern = [Regex]::Escape($UserName)
    $sourcePattern = [Regex]::Escape($SourceAddress)
    $fingerprintPattern = [Regex]::Escape($FingerprintToken)
    $matches = @($events | Where-Object {
        $message = [string]$_.Message
        $message -match "(?i)Accepted\s+publickey\s+for\s+$userPattern\s+from\s+$sourcePattern\s+port\s+[0-9]+.*$fingerprintPattern"
    } | Sort-Object TimeCreated -Descending)
    if ($matches.Count -eq 0) { throw 'No host-observed OpenSSH public-key acceptance event matches this user, Tailscale source address, approved signing-key fingerprint, and challenge window.' }
    return $matches[0]
}

function Assert-SignedClientProof {
    param(
        $Proof,
        $StateObject,
        $Config,
        [string]$ExpectedUser,
        [DateTime]$MinimumUtc,
        [string]$StateDirectory
    )
    $proofFields = @('schemaVersion', 'generatedUtc', 'targetUser', 'hostKeyFingerprint', 'scannedFingerprintToken', 'port', 'remoteIdentity', 'sourceAddress', 'serverAddress', 'nonce', 'challenge', 'signingKeyFingerprintToken', 'signedPayloadBase64', 'signatureBase64')
    $proofProperties = @($Proof.PSObject.Properties.Name)
    if (@($proofFields | Where-Object { $_ -notin $proofProperties }).Count -gt 0 -or [int]$Proof.schemaVersion -ne 2) { throw 'Client proof schema is incomplete or unsupported.' }
    $stateProperties = @($StateObject.PSObject.Properties.Name)
    if (@('clientProofChallenge', 'clientProofChallengeCreatedUtc', 'authorizedKeysPath', 'publicKeyFingerprints', 'approvedKeyCount', 'hostKeyFingerprint', 'tailscaleIPv4', 'tailscaleIPv6') | Where-Object { $_ -notin $stateProperties }) { throw 'Access state does not contain the signed-proof challenge, approved-key material, or bound Tailscale addresses.' }
    if ([string]$Proof.challenge -notmatch '^[a-f0-9]{64}$' -or [string]$Proof.challenge -cne [string]$StateObject.clientProofChallenge) { throw 'Client proof does not answer the current host-issued challenge.' }

    try {
        $payloadBytes = [Convert]::FromBase64String([string]$Proof.signedPayloadBase64)
        $signatureBytes = [Convert]::FromBase64String([string]$Proof.signatureBase64)
    }
    catch { throw 'Client proof payload or signature is not valid base64.' }
    if ($payloadBytes.Count -lt 2 -or $payloadBytes.Count -gt 16384 -or $signatureBytes.Count -lt 16 -or $signatureBytes.Count -gt 16384) { throw 'Client proof payload or signature has an unsafe size.' }
    try {
        $strictUtf8 = New-Object Text.UTF8Encoding($false, $true)
        $payloadText = $strictUtf8.GetString($payloadBytes)
        $payload = $payloadText | ConvertFrom-Json
    }
    catch { throw 'Signed client-proof payload is not valid UTF-8 JSON.' }
    $payloadFields = @('schemaVersion', 'generatedUtc', 'targetUser', 'hostKeyFingerprint', 'scannedFingerprintToken', 'port', 'remoteIdentity', 'sourceAddress', 'serverAddress', 'nonce', 'challenge', 'signingKeyFingerprintToken')
    $payloadProperties = @($payload.PSObject.Properties.Name)
    if (@($payloadFields | Where-Object { $_ -notin $payloadProperties }).Count -gt 0 -or [int]$payload.schemaVersion -ne 2) { throw 'Signed client-proof payload schema is incomplete or unsupported.' }
    foreach ($field in $payloadFields) {
        if ([string]$payload.$field -cne [string]$Proof.$field) { throw "Unsigned client-proof field differs from signed payload: $field" }
    }
    if ([string]$payload.challenge -cne [string]$StateObject.clientProofChallenge) { throw 'Signed proof challenge does not match access state.' }
    if ([string]$payload.targetUser -ine $ExpectedUser -or [int]$payload.port -ne [int]$Config.access.ssh.port) { throw 'Signed proof user or port does not match the reviewed configuration.' }
    if ([string]$payload.hostKeyFingerprint -cne [string]$StateObject.hostKeyFingerprint) { throw 'Signed proof host fingerprint does not match the locally recorded host key.' }
    $expectedHostToken = Get-Sha256FingerprintToken -Fingerprint ([string]$StateObject.hostKeyFingerprint)
    if ([string]$payload.scannedFingerprintToken -cne $expectedHostToken) { throw 'Signed proof scanned host-key token does not match the local host key.' }
    if ([string]$payload.nonce -notmatch '^[a-f0-9]{32}$') { throw 'Signed proof nonce is malformed.' }
    $identityLeaf = ([string]$payload.remoteIdentity -split '\\')[-1]
    if ($identityLeaf -ine $ExpectedUser) { throw 'Signed proof remote identity does not match the target Windows account.' }
    if (-not (Test-TailscaleSourceAddress -Address ([string]$payload.sourceAddress))) { throw 'Signed proof source address is not in a Tailscale address range.' }
    $proofServerIp = Get-CanonicalIpAddress -Address ([string]$payload.serverAddress)
    $allowedServerIps = New-Object System.Collections.Generic.List[System.Net.IPAddress]
    $allowedServerIps.Add((Get-CanonicalIpAddress -Address ([string]$StateObject.tailscaleIPv4)))
    if (-not [string]::IsNullOrWhiteSpace([string]$StateObject.tailscaleIPv6)) { $allowedServerIps.Add((Get-CanonicalIpAddress -Address ([string]$StateObject.tailscaleIPv6))) }
    if (-not [bool]($allowedServerIps | Where-Object { $_.Equals($proofServerIp) })) { throw 'Signed SSH_CONNECTION server address is not one of the protected state Tailscale addresses.' }
    try { $proofTime = [DateTime]::Parse([string]$payload.generatedUtc).ToUniversalTime() }
    catch { throw 'Signed proof timestamp is invalid.' }
    if (($proofTime - [DateTime]::UtcNow).TotalMinutes -gt 5 -or ([DateTime]::UtcNow - $proofTime).TotalMinutes -gt 30 -or $proofTime -lt $MinimumUtc) { throw 'Signed client proof is stale, from the future, or predates its required activation/boot boundary.' }
    $challengeCreated = [DateTime]::Parse([string]$StateObject.clientProofChallengeCreatedUtc).ToUniversalTime()
    if ($proofTime -lt $challengeCreated.AddMinutes(-2)) { throw 'Signed client proof predates the host-issued challenge.' }
    $approvedTokens = @($StateObject.publicKeyFingerprints | ForEach-Object { Get-Sha256FingerprintToken -Fingerprint ([string]$_) } | Sort-Object -Unique)
    if ([string]$payload.signingKeyFingerprintToken -notin $approvedTokens) { throw 'The proof-signing key is not in the prepared public-key allowlist.' }

    $authorizedPath = [string]$StateObject.authorizedKeysPath
    Assert-ExactAuthorizedKeysAcl -StateObject $StateObject
    if (-not (Test-Path -LiteralPath $authorizedPath)) { throw 'The protected authorized-keys file is missing.' }
    $token = [Guid]::NewGuid().ToString('N')
    $keyMaterialPath = Join-Path $StateDirectory (".proof-key-$token.pub")
    $allowedSignersPath = Join-Path $StateDirectory (".allowed-signers-$token")
    $signaturePath = Join-Path $StateDirectory (".client-proof-$token.sig")
    $process = $null
    try {
        $actualTokens = New-Object System.Collections.Generic.List[string]
        $selectedKeyMaterial = $null
        foreach ($line in @(Get-Content -LiteralPath $authorizedPath | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
            if ($line -notmatch '^((?:ssh-ed25519|sk-ssh-ed25519@openssh\.com)\s+[A-Za-z0-9+/=]+)(?:\s+.*)?$') { throw 'The authorized-keys file contains an unsupported line during proof validation.' }
            $keyMaterial = $Matches[1]
            [IO.File]::WriteAllText($keyMaterialPath, $keyMaterial + "`n", [Text.Encoding]::ASCII)
            Protect-EnvoyStateFile -Path $keyMaterialPath
            $actualFingerprint = Invoke-NativeChecked -FilePath $script:SshKeygenExe -ArgumentList @('-lf', $keyMaterialPath)
            $actualToken = Get-Sha256FingerprintToken -Fingerprint $actualFingerprint
            if ($actualTokens.Contains($actualToken)) { throw 'The authorized-keys file contains a duplicate signing key.' }
            $actualTokens.Add($actualToken)
            if ($actualToken -ceq [string]$payload.signingKeyFingerprintToken) { $selectedKeyMaterial = $keyMaterial }
        }
        if ($actualTokens.Count -ne [int]$StateObject.approvedKeyCount -or $actualTokens.Count -ne $approvedTokens.Count -or @(Compare-Object @($actualTokens) $approvedTokens).Count -ne 0) { throw 'The live authorized-keys set differs from the protected prepared fingerprint allowlist.' }
        if ([string]::IsNullOrWhiteSpace($selectedKeyMaterial)) { throw 'The claimed approved signing key is not present in the exact live authorized-keys set.' }
        [IO.File]::WriteAllText($allowedSignersPath, 'envoynode ' + $selectedKeyMaterial + "`n", [Text.Encoding]::ASCII)
        [IO.File]::WriteAllBytes($signaturePath, $signatureBytes)
        Protect-EnvoyStateFile -Path $allowedSignersPath
        Protect-EnvoyStateFile -Path $signaturePath
        $sshKeygen = $script:SshKeygenExe
        if (-not (Test-Path -LiteralPath $sshKeygen)) { throw 'The trusted Windows OpenSSH ssh-keygen executable is missing.' }
        $processInfo = New-Object Diagnostics.ProcessStartInfo
        $processInfo.FileName = $sshKeygen
        $processInfo.Arguments = "-Y verify -f $allowedSignersPath -I envoynode -n envoynode-client-proof -s $signaturePath"
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $true
        $processInfo.RedirectStandardInput = $true
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $processInfo
        if (-not $process.Start()) { throw 'Could not start ssh-keygen signature verification.' }
        $process.StandardInput.Write($payloadText)
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw "Client proof signature is invalid. $stdout $stderr" }
        $eventNotBefore = if ($MinimumUtc -gt $challengeCreated) { $MinimumUtc } else { $challengeCreated }
        $observedEvent = Get-HostObservedSshAuthentication -UserName $ExpectedUser -SourceAddress ([string]$payload.sourceAddress) -FingerprintToken ([string]$payload.signingKeyFingerprintToken) -NotBeforeUtc $eventNotBefore -NotAfterUtc $proofTime.AddMinutes(2)
        return [pscustomobject]@{
            Payload = $payload
            GeneratedUtc = $proofTime
            SigningKeyFingerprintToken = [string]$payload.signingKeyFingerprintToken
            HostEventRecordId = [long]$observedEvent.RecordId
            HostEventUtc = $observedEvent.TimeCreated.ToUniversalTime()
        }
    }
    finally {
        Remove-Item -LiteralPath $allowedSignersPath, $signaturePath, $keyMaterialPath -Force -ErrorAction SilentlyContinue
        if ($process) { $process.Dispose() }
    }
}

function Test-FirewallRecordAppliesToProgram {
    param($Record, [string]$ProgramPath, [string]$ServiceName)
    $programs = @($Record.Program | ForEach-Object { [Environment]::ExpandEnvironmentVariables([string]$_) })
    $services = @($Record.Service | ForEach-Object { [string]$_ })
    $programApplies = $programs.Count -eq 0 -or [bool]($programs | Where-Object {
        $_ -in @('Any', '*') -or $_ -ieq $ProgramPath
    })
    $serviceApplies = $services.Count -eq 0 -or [bool]($services | Where-Object {
        $_ -in @('Any', '*') -or $_ -ieq $ServiceName
    })
    return [bool]($programApplies -and $serviceApplies)
}

function Invoke-NativeChecked {
    param([string]$FilePath, [string[]]$ArgumentList)
    $prior = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = (& $FilePath @ArgumentList 2>&1 | Out-String).Trim()
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prior
    }
    if ($code -ne 0) { throw "$FilePath failed with exit code $code. $output" }
    return $output
}

function Assert-SshdServiceIdentity {
    param([Parameter(Mandatory = $true)][string]$ExpectedExecutable, [switch]$RequireRunning)
    if (-not (Test-Path -LiteralPath $ExpectedExecutable -PathType Leaf)) { throw 'The fixed Windows OpenSSH sshd executable is missing.' }
    $expectedResolved = (Resolve-Path -LiteralPath $ExpectedExecutable).Path
    if ((Get-AuthenticodeSignature -FilePath $expectedResolved).Status -ne 'Valid') { throw 'The fixed Windows OpenSSH sshd executable does not have a valid Authenticode signature.' }
    $services = @(Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop)
    if ($services.Count -ne 1) { throw "Expected exactly one sshd service registration; found $($services.Count)." }
    $service = $services[0]
    $registeredCommand = [Environment]::ExpandEnvironmentVariables(([string]$service.PathName).Trim())
    if ($registeredCommand -match '^"([^\"]+)"$') { $registeredExecutable = $Matches[1] }
    elseif ($registeredCommand -match '^(\S+)$') { $registeredExecutable = $Matches[1] }
    else { throw 'The sshd service command must contain only the fixed executable and no alternate configuration or other arguments.' }
    if (-not (Test-Path -LiteralPath $registeredExecutable -PathType Leaf) -or (Resolve-Path -LiteralPath $registeredExecutable).Path -ine $expectedResolved) { throw 'The sshd service registration does not point to the fixed Windows OpenSSH executable.' }
    if ([string]$service.StartName -ne 'LocalSystem') { throw "The sshd service runs as '$($service.StartName)', not the expected LocalSystem account." }
    if ($RequireRunning -and ([string]$service.State -ne 'Running' -or [int]$service.ProcessId -le 0)) { throw 'The sshd service is not running with a valid process ID.' }
    if ([string]$service.State -eq 'Running') {
        if ([int]$service.ProcessId -le 0) { throw 'The running sshd service has no valid process ID.' }
        $processes = @(Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$service.ProcessId)" -ErrorAction Stop)
        if ($processes.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$processes[0].ExecutablePath)) { throw 'The live sshd service process path could not be resolved conclusively.' }
        $liveExecutable = (Resolve-Path -LiteralPath ([string]$processes[0].ExecutablePath)).Path
        if ($liveExecutable -ine $expectedResolved) { throw 'The live sshd service process is not the fixed Windows OpenSSH executable.' }
    }
    return $service
}

function Get-TargetAccount {
    param([string]$Name)
    $account = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    if (-not $account) { throw "Local Windows account not found: $Name" }
    $adminMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
    $isAdmin = [bool]($adminMembers | Where-Object { $_.SID.Value -eq $account.SID.Value })
    return [pscustomobject]@{ Account = $account; IsAdministrator = $isAdmin }
}

function Get-TailscaleCommand {
    $nativeProgramFiles = if ([string]::IsNullOrWhiteSpace($env:ProgramW6432)) { $env:ProgramFiles } else { $env:ProgramW6432 }
    $commandPath = Join-Path $nativeProgramFiles 'Tailscale\tailscale.exe'
    if (-not (Test-Path -LiteralPath $commandPath)) { return $null }
    $resolvedCommand = (Resolve-Path -LiteralPath $commandPath).Path
    if ((Get-AuthenticodeSignature -FilePath $resolvedCommand).Status -ne 'Valid') { throw 'The fixed-path Tailscale CLI does not have a valid Authenticode signature.' }
    $service = Get-CimInstance Win32_Service -Filter "Name='Tailscale'" -ErrorAction SilentlyContinue
    if (-not $service) { throw 'The registered Tailscale Windows service is missing.' }
    $serviceCommand = [string]$service.PathName
    if ($serviceCommand -match '^\s*"([^"]+\.exe)"') { $serviceExecutable = $Matches[1] }
    elseif ($serviceCommand -match '^\s*([^\s]+\.exe)') { $serviceExecutable = $Matches[1] }
    else { throw 'The registered Tailscale service executable path is malformed.' }
    if (-not (Test-Path -LiteralPath $serviceExecutable)) { throw 'The registered Tailscale service executable is missing.' }
    $resolvedService = (Resolve-Path -LiteralPath $serviceExecutable).Path
    $trustedDirectory = (Resolve-Path -LiteralPath (Split-Path $resolvedCommand -Parent)).Path.TrimEnd('\') + '\'
    if (-not $resolvedService.StartsWith($trustedDirectory, [StringComparison]::OrdinalIgnoreCase)) { throw 'The Tailscale service executable is outside the trusted Program Files installation directory.' }
    if ((Get-AuthenticodeSignature -FilePath $resolvedService).Status -ne 'Valid') { throw 'The registered Tailscale service executable does not have a valid Authenticode signature.' }
    return $resolvedCommand
}

function Test-JsonTopLevelObjectEmpty {
    param($Value)
    if ($Value -is [Collections.IDictionary]) { return $Value.Count -eq 0 }
    if ($Value -is [Management.Automation.PSCustomObject]) { return @($Value.PSObject.Properties).Count -eq 0 }
    return $false
}

function Test-JsonCollectionEmptyOrNull {
    param($Value)
    if ($null -eq $Value) { return $true }
    if ($Value -is [Collections.IDictionary]) { return $Value.Count -eq 0 }
    if ($Value -is [Management.Automation.PSCustomObject]) { return @($Value.PSObject.Properties).Count -eq 0 }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [string]) { return @($Value).Count -eq 0 }
    return $false
}

function Test-TailscaleDriveListEmpty {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $lines = @($Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($lines.Count -lt 2 -or $lines[0] -notmatch '^name\s{2,}path\s{2,}as$' -or $lines[1] -notmatch '^-{4,}\s{2,}-{4,}\s{2,}-{2,}$') { return $null }
    return [bool]($lines.Count -eq 2)
}

function Get-TailscaleNetwork {
    $command = Get-TailscaleCommand
    if (-not $command) { throw 'Tailscale is not installed.' }
    $tailscaleService = Get-Service -Name Tailscale -ErrorAction Stop
    if ($tailscaleService.Status -ne 'Running' -or $tailscaleService.StartType -ne 'Automatic') { throw 'The trusted Tailscale Windows service must be running with Automatic startup before access activation or reboot proof.' }
    $versionText = Invoke-NativeChecked -FilePath $command -ArgumentList @('version')
    if ($versionText -notmatch '(?m)^\s*(\d+)\.(\d+)\.(\d+)') { throw 'The Tailscale client version could not be parsed.' }
    $clientVersion = [Version]::new([int]$Matches[1], [int]$Matches[2], [int]$Matches[3])
    if ($clientVersion -lt [Version]::new(1, 98, 9)) { throw 'Tailscale 1.98.9 or newer is required by the reviewed security floor and to prove persistent Serve/Funnel/Services/Taildrive state. Upgrade the official client first.' }
    $statusText = Invoke-NativeChecked -FilePath $command -ArgumentList @('status', '--json')
    $status = $statusText | ConvertFrom-Json
    $statusProperties = @($status.PSObject.Properties.Name)
    if ('Version' -notin $statusProperties -or [string]::IsNullOrWhiteSpace([string]$status.Version) -or [string]$status.Version -notmatch '^\s*(\d+)\.(\d+)\.(\d+)') { throw 'The running Tailscale daemon version could not be parsed from status --json.' }
    $daemonVersion = [Version]::new([int]$Matches[1], [int]$Matches[2], [int]$Matches[3])
    if ($daemonVersion -lt [Version]::new(1, 98, 9)) { throw 'The running Tailscale daemon is older than the required 1.98.9 security floor.' }
    if ($daemonVersion -ne $clientVersion) { throw "The Tailscale CLI ($clientVersion) and running daemon ($daemonVersion) versions do not match. Repair or restart the official installation before activation." }
    if ($status.BackendState -ne 'Running' -or -not $status.Self.Online) {
        throw 'Tailscale is not online. Complete interactive login, device approval, and tailnet policy review first.'
    }
    $prefs = (Invoke-NativeChecked -FilePath $command -ArgumentList @('debug', 'prefs')) | ConvertFrom-Json
    $prefNames = @($prefs.PSObject.Properties.Name)
    $requiredPrefs = @('ForceDaemon', 'RunSSH', 'RunWebClient', 'RemoteConfig', 'AdvertiseRoutes', 'ExitNodeIP', 'ShieldsUp')
    if (@($requiredPrefs | Where-Object { $_ -notin $prefNames }).Count -gt 0) { throw 'This Tailscale version did not expose the preferences required for unattended safety verification.' }
    if (-not $prefs.ForceDaemon) { throw 'Tailscale unattended mode is not active. Run tailscale up --unattended=true from an elevated console, then re-check.' }
    if ($prefs.RunSSH -or $prefs.RunWebClient -or $prefs.RemoteConfig -or @($prefs.AdvertiseRoutes).Count -gt 0 -or -not [string]::IsNullOrWhiteSpace([string]$prefs.ExitNodeIP)) {
        throw 'Unexpected Tailscale server, remote-management, exit-node, or subnet-routing features are enabled. Disable them before SSH activation.'
    }
    if ($prefs.ShieldsUp) { throw 'Tailscale incoming connections are disabled (shields-up). SSH cannot be accepted from the approved client.' }
    $serveText = Invoke-NativeChecked -FilePath $command -ArgumentList @('serve', 'status', '--json')
    $funnelText = Invoke-NativeChecked -FilePath $command -ArgumentList @('funnel', 'status', '--json')
    $servicesText = Invoke-NativeChecked -FilePath $command -ArgumentList @('serve', 'get-config', '--all')
    $driveText = Invoke-NativeChecked -FilePath $command -ArgumentList @('drive', 'list')
    if ([string]::IsNullOrWhiteSpace($serveText) -or [string]::IsNullOrWhiteSpace($funnelText) -or [string]::IsNullOrWhiteSpace($servicesText)) { throw 'Tailscale Serve/Funnel/Services inspection returned no conclusive JSON.' }
    try {
        $serveStatus = $serveText | ConvertFrom-Json
        $funnelStatus = $funnelText | ConvertFrom-Json
        $servicesConfig = $servicesText | ConvertFrom-Json
    }
    catch { throw 'Tailscale Serve/Funnel/Services status was not valid JSON. Refusing activation.' }
    if (-not (Test-JsonTopLevelObjectEmpty -Value $serveStatus) -or -not (Test-JsonTopLevelObjectEmpty -Value $funnelStatus)) {
        throw 'Persistent Tailscale Serve or Funnel forwarding is configured. Reset it explicitly and review a fresh plan before activation.'
    }
    $serviceProperties = @($servicesConfig.PSObject.Properties.Name)
    $unknownServiceProperties = @($serviceProperties | Where-Object { $_ -notin @('version', 'services') })
    if ('version' -notin $serviceProperties -or [string]$servicesConfig.version -cne '0.0.1' -or $unknownServiceProperties.Count -gt 0) { throw 'Tailscale Services configuration schema was not recognized conclusively.' }
    $servicesValue = if ('services' -in $serviceProperties) { $servicesConfig.services } else { $null }
    if (-not (Test-JsonCollectionEmptyOrNull -Value $servicesValue)) { throw 'Persistent Tailscale Services forwarding is configured. Remove it and review a fresh plan before activation.' }
    $driveEmpty = Test-TailscaleDriveListEmpty -Text $driveText
    if ($null -eq $driveEmpty) { throw 'Tailscale Taildrive share state could not be parsed conclusively. Refusing activation.' }
    if (-not $driveEmpty) { throw 'One or more Taildrive directories are shared from this host. Unshare them and review a fresh plan before activation.' }
    $ipv4 = (Invoke-NativeChecked -FilePath $command -ArgumentList @('ip', '-4')).Trim()
    $ipv6 = $null
    try { $ipv6 = (Invoke-NativeChecked -FilePath $command -ArgumentList @('ip', '-6')).Trim() } catch { }
    $ipObject = Get-NetIPAddress -IPAddress $ipv4 -ErrorAction Stop
    $adapters = @(Get-NetAdapter -InterfaceIndex $ipObject.InterfaceIndex -ErrorAction Stop)
    if ($adapters.Count -ne 1) { throw "Expected exactly one adapter for the Tailscale IPv4 address; found $($adapters.Count)." }
    return [pscustomobject]@{ Command = $command; Status = $status; IPv4 = $ipv4; IPv6 = $ipv6; Adapter = $adapters[0]; ServeConfigEmpty = $true; FunnelConfigEmpty = $true; ServicesConfigEmpty = $true; DriveSharesEmpty = $true }
}

function Assert-TailscaleHostKeyExpiry {
    param($Status, [string]$Policy)
    $selfProperties = @($Status.Self.PSObject.Properties.Name)
    $hasExpiry = $selfProperties -contains 'KeyExpiry' -and -not [string]::IsNullOrWhiteSpace([string]$Status.Self.KeyExpiry)
    switch ($Policy) {
        'keep-enabled' {
            if (-not $hasExpiry) { throw 'Configuration requires Tailscale node-key expiry, but the admin setting appears disabled for this host.' }
            try { $expiry = [DateTime]::Parse([string]$Status.Self.KeyExpiry).ToUniversalTime() }
            catch { throw 'Tailscale returned an unreadable node-key expiry time. Refusing unattended activation.' }
            $reportedExpired = $selfProperties -contains 'Expired' -and [bool]$Status.Self.Expired
            if ($reportedExpired -or $expiry -le [DateTime]::UtcNow) { throw 'The Tailscale node key is expired. Reauthenticate locally before enabling access.' }
            if ($expiry -lt [DateTime]::UtcNow.AddDays(30)) { throw "The Tailscale node key expires at $($expiry.ToString('o')), inside the 30-day unattended readiness window. Reauthenticate locally first." }
        }
        'disable-for-unattended-host' {
            if ($hasExpiry) { throw 'Configuration explicitly selects a non-expiring unattended host, but Tailscale node-key expiry is still enabled for this device.' }
        }
        default {
            throw "Unsupported access.overlay.hostKeyExpiry value '$Policy'. Use 'keep-enabled' or 'disable-for-unattended-host'."
        }
    }
}

function Get-AuthorizedKeyTarget {
    param($AccountInfo)
    if ($AccountInfo.IsAdministrator) {
        $programDataPath = [IO.Path]::GetFullPath($env:ProgramData)
        Assert-NoReparsePathChain -Path $programDataPath -RequireDirectoryLeaf
        $adminKeyPath = [IO.Path]::GetFullPath((Join-Path $programDataPath 'ssh\administrators_authorized_keys'))
        Assert-NoReparsePathChain -Path (Split-Path $adminKeyPath -Parent)
        Assert-NoReparsePathChain -Path $adminKeyPath
        return [pscustomobject]@{ Path = $adminKeyPath; IsAdministrator = $true; UserSid = $AccountInfo.Account.SID.Value }
    }
    $sid = $AccountInfo.Account.SID.Value
    $profile = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ErrorAction SilentlyContinue
    if (-not $profile -or [string]::IsNullOrWhiteSpace($profile.ProfileImagePath)) {
        throw 'The standard account has no initialized Windows profile. Sign in locally once, then rerun Prepare.'
    }
    $profilePath = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($profile.ProfileImagePath))
    Assert-NoReparsePathChain -Path $profilePath -RequireDirectoryLeaf
    $standardKeyPath = [IO.Path]::GetFullPath((Join-Path $profilePath '.ssh\authorized_keys'))
    Assert-NoReparsePathChain -Path (Split-Path $standardKeyPath -Parent)
    Assert-NoReparsePathChain -Path $standardKeyPath
    return [pscustomobject]@{ Path = $standardKeyPath; IsAdministrator = $false; UserSid = $sid }
}

function Set-AuthorizedPublicKeys {
    param([string[]]$KeyPaths, $Target, [string]$BackupDirectory)
    $material = New-Object System.Collections.Generic.List[object]
    foreach ($keyPath in $KeyPaths) {
        if (-not (Test-Path -LiteralPath $keyPath)) { throw "Public key file not found: $keyPath" }
        $keyText = (Get-Content -LiteralPath $keyPath -Raw).Trim()
        if ($keyText -match 'PRIVATE KEY') { throw 'A private key was supplied. Only .pub files are allowed.' }
        if ($keyText -notmatch '^(ssh-ed25519|sk-ssh-ed25519@openssh\.com)\s+[A-Za-z0-9+/=]+(?:\s+.*)?$') {
            throw 'Every configured key file must contain exactly one Ed25519 or hardware-backed Ed25519 public-key line.'
        }
        $fingerprint = Invoke-NativeChecked -FilePath $script:SshKeygenExe -ArgumentList @('-lf', (Resolve-Path -LiteralPath $keyPath).Path)
        $material.Add([pscustomobject]@{ Line = $keyText; Fingerprint = $fingerprint })
    }
    $desiredLines = @($material.Line | Select-Object -Unique)
    if ($desiredLines.Count -ne $material.Count) { throw 'Duplicate public keys are configured. Keep each approved key exactly once.' }
    $directory = Split-Path $Target.Path -Parent
    Assert-NoReparsePathChain -Path $directory
    Assert-NoReparsePathChain -Path $Target.Path
    if (-not (Test-Path -LiteralPath $directory)) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
    Assert-NoReparsePathChain -Path $directory -RequireDirectoryLeaf
    Assert-NoReparsePathChain -Path $Target.Path
    if (-not $Target.IsAdministrator) {
        Set-ExactStandardSshDirectoryAcl -Path $directory -TargetSid ([string]$Target.UserSid)
        Assert-ExactStandardSshDirectoryAcl -Path $directory -TargetSid ([string]$Target.UserSid)
    }
    $existing = if (Test-Path -LiteralPath $Target.Path) { @(Get-Content -LiteralPath $Target.Path | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } else { @() }
    $unexpected = @($existing | Where-Object { $_ -notin $desiredLines })
    if ($unexpected.Count -gt 0) {
        throw "The existing authorized-keys file contains $($unexpected.Count) line(s) outside the reviewed config allowlist. Add every intentionally retained public key to access.ssh.publicKeyFiles before Prepare."
    }
    Protect-EnvoyStateDirectory -Path $BackupDirectory
    $backupPath = $null
    if (Test-Path -LiteralPath $Target.Path) {
        Assert-NoReparsePathChain -Path $Target.Path -RequireFileLeaf
        $backupPath = Join-Path $BackupDirectory ('authorized_keys-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff') + '.bak')
        Copy-EnvoyStateFile -Source $Target.Path -Destination $backupPath
    }
    $temporaryPath = Join-Path $directory ('.envoy-authorized-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        Assert-NoReparsePathChain -Path $directory -RequireDirectoryLeaf
        Assert-NoReparsePathChain -Path $Target.Path
        [IO.File]::WriteAllLines($temporaryPath, $desiredLines, [Text.Encoding]::ASCII)
        if ($Target.IsAdministrator) {
            Invoke-NativeChecked -FilePath $script:IcaclsExe -ArgumentList @($temporaryPath, '/inheritance:r', '/grant:r', '*S-1-5-32-544:F', '*S-1-5-18:F') | Out-Null
        }
        else {
            Assert-ExactStandardSshDirectoryAcl -Path $directory -TargetSid ([string]$Target.UserSid)
            Invoke-NativeChecked -FilePath $script:IcaclsExe -ArgumentList @($temporaryPath, '/inheritance:r', '/grant:r', "*$($Target.UserSid):F", '*S-1-5-18:F', '*S-1-5-32-544:F') | Out-Null
        }
        Assert-NoReparsePathChain -Path $directory -RequireDirectoryLeaf
        Assert-NoReparsePathChain -Path $Target.Path
        Move-Item -LiteralPath $temporaryPath -Destination $Target.Path -Force
    }
    finally { Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue }
    if ($Target.IsAdministrator) {
        Assert-NoReparsePathChain -Path $Target.Path -RequireFileLeaf
        Invoke-NativeChecked -FilePath $script:IcaclsExe -ArgumentList @($Target.Path, '/inheritance:r', '/grant:r', '*S-1-5-32-544:F', '*S-1-5-18:F') | Out-Null
    }
    else {
        Set-ExactStandardSshDirectoryAcl -Path $directory -TargetSid ([string]$Target.UserSid)
        Assert-ExactStandardSshDirectoryAcl -Path $directory -TargetSid ([string]$Target.UserSid)
        Assert-NoReparsePathChain -Path $Target.Path -RequireFileLeaf
        Invoke-NativeChecked -FilePath $script:IcaclsExe -ArgumentList @($Target.Path, '/inheritance:r', '/grant:r', "*$($Target.UserSid):F", '*S-1-5-18:F', '*S-1-5-32-544:F') | Out-Null
    }
    Assert-ExactAuthorizedKeysAcl -StateObject ([pscustomobject]@{ authorizedKeysPath = $Target.Path; targetIsAdministrator = [bool]$Target.IsAdministrator; targetSid = [string]$Target.UserSid })
    return [pscustomobject]@{ Fingerprints = @($material.Fingerprint); KeyCount = $desiredLines.Count; BackupPath = $backupPath }
}

function Get-ManagedSshBlock {
    param($Config, [string]$UserName, [bool]$Hardened, [string]$AuthorizedKeysPath)
    $forward = if ($Config.access.ssh.allowLocalPortForwarding) { 'local' } else { 'no' }
    $password = if ($Hardened) { 'no' } else { 'yes' }
    $authorizedKeys = $AuthorizedKeysPath.Replace('\', '/')
    $lines = @(
        '# BEGIN EnvoyNode managed global settings',
        "Port $($Config.access.ssh.port)",
        'PubkeyAuthentication yes',
        "AuthorizedKeysFile `"$authorizedKeys`"",
        'TrustedUserCAKeys none',
        'GSSAPIAuthentication no',
        "PasswordAuthentication $password",
        "AuthenticationMethods $(if ($Hardened) { 'publickey' } else { 'publickey password' })",
        'PermitEmptyPasswords no',
        "AllowUsers $($UserName.ToLowerInvariant())",
        'AllowAgentForwarding no',
        "AllowTcpForwarding $forward",
        'GatewayPorts no',
        'MaxAuthTries 3',
        'LoginGraceTime 30',
        'LogLevel VERBOSE'
    )
    if ($forward -eq 'local' -and @($Config.access.ssh.allowedForwardTargets).Count -gt 0) {
        foreach ($target in @($Config.access.ssh.allowedForwardTargets)) {
            if ([string]$target -notmatch '^(127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})$') { throw "Unsafe SSH forwarding target: $target" }
        }
        $lines += 'PermitOpen ' + (@($Config.access.ssh.allowedForwardTargets) -join ' ')
    }
    else {
        $lines += 'PermitOpen none'
    }
    $lines += '# END EnvoyNode managed global settings'
    return ($lines -join "`r`n") + "`r`n"
}

function Set-ManagedSshBlock {
    param([string]$ConfigPathOnHost, [string]$Block)
    $original = if (Test-Path -LiteralPath $ConfigPathOnHost) { [IO.File]::ReadAllText($ConfigPathOnHost) } else { '' }
    $pattern = '(?ms)^# BEGIN EnvoyNode managed global settings\r?\n.*?^# END EnvoyNode managed global settings\r?\n?'
    if ($original -match $pattern) { $updated = [regex]::Replace($original, $pattern, $Block, 1) }
    else { $updated = $Block + $original }
    [IO.File]::WriteAllText($ConfigPathOnHost, $updated, (New-Object Text.UTF8Encoding($false)))
}

function Assert-NoUnsafeUnmanagedSshDirectives {
    param([string]$ConfigPathOnHost)
    $text = [IO.File]::ReadAllText($ConfigPathOnHost)
    $managedPattern = '(?ms)^# BEGIN EnvoyNode managed global settings\r?\n.*?^# END EnvoyNode managed global settings\r?\n?'
    $managedMatches = @([regex]::Matches($text, $managedPattern))
    if ($managedMatches.Count -ne 1) { throw 'Exactly one EnvoyNode-managed global SSH block is required.' }
    $unmanaged = [regex]::Replace($text, $managedPattern, '', 1)
    $active = @($unmanaged -split "`r?`n" | ForEach-Object { ($_ -replace '\s+#.*$', '').Trim() } | Where-Object { $_ })
    if (@($active | Where-Object { $_ -match '(?i)^Include\s+' }).Count -gt 0) {
        throw 'Active unmanaged Include directives are not allowed because their Match scope cannot be bounded safely.'
    }
    if (@($active | Where-Object { $_ -match '(?i)^(AuthorizedKeysCommand|AuthorizedKeysCommandUser|AuthorizedPrincipalsCommand|AuthorizedPrincipalsCommandUser)\s+' }).Count -gt 0) {
        throw 'Unmanaged external authorized-key or principal commands are forbidden; configured public-key files are the only key authority.'
    }
    $matchIndexes = @(for ($i = 0; $i -lt $active.Count; $i++) { if ($active[$i] -match '(?i)^Match\s+') { $i } })
    if ($matchIndexes.Count -gt 1) { throw 'More than one unmanaged Match block is active.' }
    if ($matchIndexes.Count -eq 1) {
        $matchIndex = [int]$matchIndexes[0]
        $matchLine = (($active[$matchIndex] -replace '\s+', ' ').Trim())
        $tail = if ($matchIndex -lt ($active.Count - 1)) { @($active[($matchIndex + 1)..($active.Count - 1)] | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) }) } else { @() }
        if ($matchLine -ine 'Match Group administrators' -or $tail.Count -ne 1 -or $tail[0] -ine 'AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys') {
            throw 'The only allowed unmanaged Match block is the exact Microsoft administrators_authorized_keys compatibility tail.'
        }
    }
}

function Assert-EffectiveSshConfiguration {
    param([string]$Executable, [string]$ConfigPathOnHost, $Config, [string]$UserName, [bool]$Hardened, [string]$AuthorizedKeysPath, [string]$SourceAddress, [string]$LocalAddress)
    $effectiveText = Invoke-NativeChecked -FilePath $Executable -ArgumentList @('-T', '-f', $ConfigPathOnHost, '-C', "user=$UserName,host=localhost,addr=127.0.0.1")
    $settings = @{}
    foreach ($line in @($effectiveText -split "`r?`n")) {
        if ($line -match '^([^\s]+)\s+(.*)$') {
            $name = $Matches[1].ToLowerInvariant()
            $value = $Matches[2].Trim()
            $settings[$name] = @($settings[$name]) + $value
        }
    }
    $expectedScalars = [ordered]@{
        pubkeyauthentication = 'yes'
        authorizedkeysfile = $AuthorizedKeysPath.Replace('\', '/')
        trustedusercakeys = 'none'
        gssapiauthentication = 'no'
        passwordauthentication = if ($Hardened) { 'no' } else { 'yes' }
        authenticationmethods = if ($Hardened) { 'publickey' } else { 'publickey password' }
        allowagentforwarding = 'no'
        allowtcpforwarding = if ($Config.access.ssh.allowLocalPortForwarding) { 'local' } else { 'no' }
        gatewayports = 'no'
        permitemptypasswords = 'no'
        maxauthtries = '3'
        logingracetime = '30'
        loglevel = 'verbose'
    }
    foreach ($entry in $expectedScalars.GetEnumerator()) {
        $observed = @($settings[$entry.Key] | Sort-Object -Unique)
        if ($observed.Count -ne 1 -or $observed[0] -ine [string]$entry.Value) {
            throw "Effective sshd setting '$($entry.Key)' is '$($observed -join ',')', expected '$($entry.Value)'. An Include, Match, or unmanaged directive may conflict."
        }
    }
    $ports = @($settings['port'] | ForEach-Object { @($_ -split '\s+') } | Where-Object { $_ } | Sort-Object -Unique)
    if ($ports.Count -ne 1 -or $ports[0] -ne [string][int]$Config.access.ssh.port) { throw "Effective sshd ports are '$($ports -join ',')'; exactly one configured port is required." }
    foreach ($listenAddress in @($settings['listenaddress'])) {
        if ($listenAddress -notmatch ':(\d+)$' -or [int]$Matches[1] -ne [int]$Config.access.ssh.port) { throw "Unexpected effective ListenAddress: $listenAddress" }
    }
    $allowedUsers = @($settings['allowusers'] | ForEach-Object { @($_ -split '\s+') } | Where-Object { $_ } | Sort-Object -Unique)
    if ($allowedUsers.Count -ne 1 -or $allowedUsers[0] -ine $UserName) { throw "Effective AllowUsers is '$($allowedUsers -join ',')'; exactly the target account is required." }
    $expectedPermitOpen = if ($Config.access.ssh.allowLocalPortForwarding -and @($Config.access.ssh.allowedForwardTargets).Count -gt 0) { @($Config.access.ssh.allowedForwardTargets) } else { @('none') }
    $actualPermitOpen = @($settings['permitopen'] | ForEach-Object { @($_ -split '\s+') } | Where-Object { $_ } | Sort-Object -Unique)
    $expectedPermitOpen = @($expectedPermitOpen | Sort-Object -Unique)
    if ($actualPermitOpen.Count -ne $expectedPermitOpen.Count -or @(Compare-Object $actualPermitOpen $expectedPermitOpen).Count -ne 0) {
        throw "Effective PermitOpen is '$($actualPermitOpen -join ',')', not the reviewed local-forward allowlist."
    }
    if ($SourceAddress -and $LocalAddress) {
        $tailnetEffective = Invoke-NativeChecked -FilePath $Executable -ArgumentList @('-T', '-f', $ConfigPathOnHost, '-C', "user=$UserName,host=envoynode,addr=$SourceAddress,laddr=$LocalAddress,lport=$([int]$Config.access.ssh.port)")
        if (($tailnetEffective -replace "`r`n", "`n").Trim() -cne ($effectiveText -replace "`r`n", "`n").Trim()) { throw 'Effective SSH settings differ between localhost and the actual tailnet connection context; an unmanaged Match rule is active.' }
    }
    return $effectiveText
}

function Assert-SshdListenerOwnership {
    param([int]$Port, [string]$TailscaleIPv4, [string]$TailscaleIPv6)
    $service = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
    if ([int]$service.ProcessId -le 0) { throw 'sshd has no running service process.' }
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.OwningProcess -eq [int]$service.ProcessId })
    $udpEndpoints = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { $_.OwningProcess -eq [int]$service.ProcessId })
    $ports = @($listeners.LocalPort | Sort-Object -Unique)
    if ($ports.Count -ne 1 -or [int]$ports[0] -ne $Port) { throw "sshd owns unexpected listener ports: $($ports -join ',')." }
    $reachable = @('0.0.0.0', '::', $TailscaleIPv4, $TailscaleIPv6) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
    if (@($listeners | Where-Object { $_.LocalAddress -in $reachable }).Count -eq 0) { throw 'sshd does not own a listener reachable through the Tailscale firewall path.' }
    if (@($listeners | Where-Object { $_.LocalAddress -notin $reachable }).Count -gt 0) { throw 'sshd owns an unexpected listener address outside the reviewed wildcard/Tailscale set.' }
    if ($udpEndpoints.Count -gt 0) { throw 'sshd unexpectedly owns one or more UDP endpoints.' }
}

$projectRoot = Split-Path $PSScriptRoot -Parent
$stateDir = Join-Path $env:ProgramData 'EnvoyNode\state'
$statePath = Join-Path $stateDir 'access-current.json'
$sshConfigDirectory = Join-Path $env:ProgramData 'ssh'
$sshdConfig = Join-Path $sshConfigDirectory 'sshd_config'
$sshdExe = Join-Path $script:WindowsSystemDirectory 'OpenSSH\sshd.exe'
$ownedRuleNames = @('EnvoyNode-SSH-Tailnet-IPv4', 'EnvoyNode-SSH-Tailnet-IPv6')
$machineFingerprint = Get-EnvoyMachineFingerprint

# Break-glass shutdown intentionally does not depend on the configured account
# still existing or on the local configuration file remaining readable.
if ($Stage -eq 'Disable') {
    if (-not $Apply) { throw 'Disable is mutating and requires -Apply from the local console.' }
    if ($WhatIfPreference) { Write-Output 'What if: stop sshd, startup-disable it, and disable EnvoyNode-owned SSH firewall rules.'; return }
    if (-not (Test-IsElevated)) { throw 'Disable must run in an elevated PowerShell window.' }
    if (-not (Test-Path -LiteralPath $statePath)) { throw 'No EnvoyNode access state exists; refusing to stop an unmanaged SSH service.' }
    Protect-EnvoyStateDirectory -Path $stateDir -AllowRepairWithContent
    if (-not (Test-ExactPrivilegedFileAcl -Path $statePath)) { throw 'Access state file ACL/owner is not the exact protected policy; refusing to trust lifecycle state.' }
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    Assert-AccessStateBinding -StateObject $state -MachineFingerprint $machineFingerprint
    $disableErrors = New-Object System.Collections.Generic.List[string]
    try { Set-Service sshd -StartupType Disabled -ErrorAction Stop } catch { $disableErrors.Add("service startup: $($_.Exception.Message)") }
    try { Stop-Service sshd -Force -ErrorAction Stop } catch { $disableErrors.Add("service stop: $($_.Exception.Message)") }
    try { Disable-EnvoyFirewallRules -Names $ownedRuleNames } catch { $disableErrors.Add("managed firewall: $($_.Exception.Message)") }
    try { Disable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore -ErrorAction Stop | Out-Null } catch {
        if (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue) { $disableErrors.Add("default firewall: $($_.Exception.Message)") }
    }
    $failCloseError = $null
    try { Assert-SshAccessFailedClosed -OwnedRuleNames $ownedRuleNames -Port ([int]$state.sshPort) }
    catch { $failCloseError = $_.Exception.Message }
    $authenticationMode = if ($state.PSObject.Properties.Name -contains 'authenticationMode') { [string]$state.authenticationMode } elseif ($state.status -eq 'hardened-key-only') { 'key-only' } else { 'bootstrap-password' }
    if ($state.status -eq 'hardened-key-only') { $authenticationMode = 'key-only' }
    Set-StateProperty -StateObject $state -Name 'authenticationModeBeforeDisable' -Value $authenticationMode
    Set-StateProperty -StateObject $state -Name 'authenticationMode' -Value $authenticationMode
    $state.status = if ([string]::IsNullOrWhiteSpace($failCloseError)) { 'disabled-break-glass' } else { 'disable-incomplete-fail-close-unproven' }
    Set-StateProperty -StateObject $state -Name 'disabledUtc' -Value ([DateTime]::UtcNow.ToString('o'))
    $observedService = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue
    Set-StateProperty -StateObject $state -Name 'serviceStartup' -Value $(if ($observedService) { [string]$observedService.StartMode } else { 'Unknown' })
    Write-EnvoyStateFile -Value $state -Path $statePath -Depth 8
    if (-not [string]::IsNullOrWhiteSpace($failCloseError)) { throw "Emergency shutdown attempted every independent closure path, but fail-close could not be proven. Use the local console immediately. $failCloseError Attempts: $($disableErrors -join '; ')" }
    Write-Output 'Managed SSH is proven stopped/startup-disabled with protected ingress off and no managed-port listener. Software, keys, backups, and Tailscale enrollment were preserved.'
    return
}

if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Configuration file not found: $ConfigPath" }
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
if ($config.access.exposePublicPorts -ne $false) { throw 'Refusing a configuration that exposes public ports.' }
if ($config.access.overlay.provider -ne 'tailscale') { throw 'Only the Tailscale overlay is supported in this release.' }
$configuredTargetUser = if ([string]::IsNullOrWhiteSpace([string]$config.access.ssh.targetUser)) { $env:USERNAME } else { [string]$config.access.ssh.targetUser }
if ([string]::IsNullOrWhiteSpace($TargetUser)) { $TargetUser = $configuredTargetUser }
elseif ($TargetUser -ine $configuredTargetUser) { throw "-TargetUser cannot override the plan-bound configured target '$configuredTargetUser'. Edit access.ssh.targetUser and generate a fresh plan." }
if ($TargetUser -notmatch '^[A-Za-z0-9._-]+$') { throw 'Unsafe target user name.' }

$accountInfo = Get-TargetAccount -Name $TargetUser
$preview = [pscustomobject][ordered]@{
    stage = $Stage
    configEnabled = [bool]$config.access.ssh.enabled
    targetUser = $TargetUser
    targetIsAdministrator = $accountInfo.IsAdministrator
    administratorKeyCaveat = if ($accountInfo.IsAdministrator) { 'Windows uses the shared ProgramData administrators_authorized_keys file. AllowUsers still limits SSH login to this account. A stolen key is a full-control credential.' } else { $null }
    publicKeyPath = $PublicKeyPath
    tailscaleInstalled = [bool](Get-TailscaleCommand)
    sshdPresent = [bool](Get-Service sshd -ErrorAction SilentlyContinue)
    plannedPorts = @([int]$config.access.ssh.port)
    publicExposureAllowed = $false
    nextGate = switch ($Stage) {
        'Preview' { 'Review this output, prepare a client .pub key, and opt in through a local config.' }
        'Prepare' { 'Install prerequisites and key while keeping sshd inaccessible.' }
        'Enable' { 'Tailscale must already be online, device-approved, MFA-backed, default-deny policy tested, and Taildrop disabled.' }
        'Harden' { 'A fresh proof from a second device is mandatory.' }
        'RebootProof' { 'After a deliberate reboot, a new key-only proof from the second device is mandatory.' }
        'Disable' { 'Run only from the local console; managed inbound access will stop.' }
    }
}

if ($Stage -eq 'Preview') { $preview | ConvertTo-Json -Depth 6; return }
if ($config.access.ssh.enabled -ne $true) { throw 'access.ssh.enabled is false. Opt in through the reviewed configuration before mutating SSH.' }
if (-not $Apply) { throw "$Stage is mutating and requires -Apply." }
if ($WhatIfPreference) { $preview | ConvertTo-Json -Depth 6; return }
if (-not (Test-IsElevated)) { throw "$Stage must run in an elevated PowerShell window." }
& (Join-Path $PSScriptRoot 'Assert-EnvoyPlanApproval.ps1') -Action ("Access" + $Stage) -ConfigPath $ConfigPath -ApprovedPlanHash $ApprovedPlanHash -ApprovedPlanPath $ApprovedPlanPath
if ($accountInfo.IsAdministrator -and -not $AcknowledgeAdministratorTarget -and $Stage -ne 'Disable') {
    throw 'The target is an administrator. Use a dedicated standard user or explicitly pass -AcknowledgeAdministratorTarget after accepting the full-control risk.'
}
if (-not (Test-Path -LiteralPath $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
Protect-EnvoyStateDirectory -Path $stateDir

if ($Stage -eq 'Prepare') {
    $configDirectory = Split-Path (Resolve-Path -LiteralPath $ConfigPath).Path -Parent
    $configuredRawKeyPaths = @($config.access.ssh.publicKeyFiles)
    if ($configuredRawKeyPaths.Count -eq 0) { throw 'At least one reviewed access.ssh.publicKeyFiles entry is required.' }
    $configuredKeyPaths = @($configuredRawKeyPaths | ForEach-Object {
        $candidate = [string]$_
        if ([string]::IsNullOrWhiteSpace($candidate)) { throw 'Configured public-key paths cannot be blank.' }
        if (-not [IO.Path]::IsPathRooted($candidate)) { $candidate = Join-Path $configDirectory $candidate }
        if (-not (Test-Path -LiteralPath $candidate)) { throw "Configured public-key file not found: $candidate" }
        (Resolve-Path -LiteralPath $candidate).Path
    })
    if (-not [string]::IsNullOrWhiteSpace($PublicKeyPath)) {
        if (-not (Test-Path -LiteralPath $PublicKeyPath)) { throw "Optional public key file not found: $PublicKeyPath" }
        $resolvedPublicKeyPath = (Resolve-Path -LiteralPath $PublicKeyPath).Path
        if (-not [bool]($configuredKeyPaths | Where-Object { $_ -ieq $resolvedPublicKeyPath })) { throw 'When supplied, -PublicKeyPath must match one of the plan-bound access.ssh.publicKeyFiles entries.' }
    }
    $previousState = $null
    if (Test-Path -LiteralPath $statePath) {
        if (-not (Test-ExactPrivilegedFileAcl -Path $statePath)) { throw 'Existing access state file ACL/owner is not the exact protected policy; refusing to resume or adopt it.' }
        $previousState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        Assert-AccessStateBinding -StateObject $previousState -MachineFingerprint $machineFingerprint -ExpectedUser $TargetUser -ExpectedSid $accountInfo.Account.SID.Value -ExpectedPort ([int]$config.access.ssh.port) -ExpectedAdministrator ([int][bool]$accountInfo.IsAdministrator)
        if ($previousState.status -notin @('prepare-in-progress', 'prepared', 'disabled-break-glass')) {
            throw "Prepare will not interrupt access while state is '$($previousState.status)'. Disable access locally first."
        }
    }
    $preexistingSshd = [bool](Get-Service sshd -ErrorAction SilentlyContinue)
    if ($preexistingSshd -and -not $previousState) {
        throw 'An unmanaged OpenSSH Server installation already exists. This release refuses automatic adoption.'
    }
    $tailscaleBefore = [bool](Get-TailscaleCommand)
    if (-not $tailscaleBefore) {
        throw 'Tailscale is absent. Install and enroll the official signed client interactively before elevated access preparation; this script never executes a user-PATH package manager as administrator.'
    }
    $keyTarget = Get-AuthorizedKeyTarget -AccountInfo $accountInfo
    if (-not $previousState) {
        $previousState = [pscustomobject][ordered]@{
            schemaVersion = 1
            machineFingerprint = $machineFingerprint
            preparedUtc = $null
            targetUser = $TargetUser
            targetSid = $accountInfo.Account.SID.Value
            targetIsAdministrator = $accountInfo.IsAdministrator
            sshPort = [int]$config.access.ssh.port
            publicKeyFingerprint = $null
            authorizedKeysPath = $keyTarget.Path
            tailscaleInstalledByRun = $false
            opensshInstalledByRun = (-not $preexistingSshd)
            defaultFirewallRuleWasEnabled = $false
            sshdConfigSha256Before = if (Test-Path -LiteralPath $sshdConfig) { (Get-FileHash -LiteralPath $sshdConfig -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
            authenticationMode = 'bootstrap-password'
            authenticationModeBeforeDisable = $null
            status = 'prepare-in-progress'
        }
        # Write ownership before package installation so a partial Windows
        # capability or winget result can be resumed without adopting an
        # unrelated OpenSSH installation.
        Write-EnvoyStateFile -Value $previousState -Path $statePath -Depth 8
    }
    Protect-SshConfigurationDirectory -Path $sshConfigDirectory
    if (-not $preexistingSshd) {
        try {
            if ($PSCmdlet.ShouldProcess('OpenSSH.Server', 'Install Windows capability')) {
                Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
            }
        }
        finally {
            Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Disable-NetFirewallRule | Out-Null
        }
    }
    $defaultRule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
    $defaultRuleWasEnabled = [bool]($defaultRule -and $defaultRule.Enabled -eq 'True')
    if ($defaultRule) { Disable-NetFirewallRule -Name $defaultRule.Name | Out-Null }
    $service = Get-Service sshd -ErrorAction Stop
    Assert-SshdServiceIdentity -ExpectedExecutable $sshdExe | Out-Null
    if ($service.Status -eq 'Running') { Stop-Service sshd -Force }
    $preStartAudit = & (Join-Path $PSScriptRoot 'Get-EnvoyAudit.ps1') -AdditionalSensitivePorts @([int]$config.access.ssh.port) -PassThru -NoReport
    if (-not $preStartAudit.access.firewallInspectionComplete) { throw 'The elevated firewall inspection was incomplete. Refusing to start or prepare sshd.' }
    if (-not $preStartAudit.access.firewallProfilesSecure) { throw 'Windows Firewall profiles are disabled, default-allow, or unverified. Refusing to prepare sshd.' }
    if (-not $preStartAudit.access.portProxyInspectionComplete -or $preStartAudit.access.localPortProxyConfigured) { throw 'Windows port-proxy inspection is incomplete or a forwarding rule exists. Refusing access preparation.' }
    if ($preStartAudit.host.pendingReboot) { throw 'Windows has a pending reboot. Complete it with local recovery available before access preparation.' }
    if (-not $preStartAudit.security.uacInspectionComplete -or -not $preStartAudit.security.uacEnabled) { throw 'User Account Control is disabled or unverified. Refusing access preparation.' }
    if (-not $preStartAudit.security.secureBootInspectionComplete -or -not $preStartAudit.security.secureBootEnabled) { throw 'Secure Boot is disabled or unverified. Refusing access preparation.' }
    $unexpectedSshRules = @($preStartAudit.access.sensitiveFirewallRules | Where-Object {
        $_.Port -eq [int]$config.access.ssh.port -and $_.Enabled -eq 'True' -and $_.Action -in @('Allow', 'Block') -and
        $_.Name -ne 'OpenSSH-Server-In-TCP' -and $_.Name -notin $ownedRuleNames -and
        (Test-FirewallRecordAppliesToProgram -Record $_ -ProgramPath $sshdExe -ServiceName 'sshd')
    })
    if ($unexpectedSshRules.Count -gt 0) { throw 'An unexpected enabled SSH allow/block firewall rule exists. Review it manually before the first sshd start.' }
    if (-not (Test-Path -LiteralPath $sshdConfig)) {
        $defaultSshdConfig = Join-Path $env:WINDIR 'System32\OpenSSH\sshd_config_default'
        if (-not (Test-Path -LiteralPath $defaultSshdConfig)) { throw 'The Microsoft OpenSSH default configuration template is missing.' }
        Copy-Item -LiteralPath $defaultSshdConfig -Destination $sshdConfig
        Invoke-NativeChecked -FilePath $script:SshKeygenExe -ArgumentList @('-A') | Out-Null
    }
    Protect-SshConfigurationFile -DirectoryPath $sshConfigDirectory -ConfigPath $sshdConfig
    $keyBackupDirectory = Join-Path $stateDir 'key-backups'
    $keyResult = Set-AuthorizedPublicKeys -KeyPaths $configuredKeyPaths -Target $keyTarget -BackupDirectory $keyBackupDirectory
    $previousProperties = if ($previousState) { @($previousState.PSObject.Properties.Name) } else { @() }
    $previousRequestedMode = if ($previousProperties -contains 'authenticationMode') { [string]$previousState.authenticationMode } elseif ($previousProperties -contains 'authenticationModeBeforeDisable') { [string]$previousState.authenticationModeBeforeDisable } else { 'bootstrap-password' }
    $preserveKeyOnly = $false
    if ($previousRequestedMode -eq 'key-only' -and $previousProperties -contains 'publicKeyFingerprints') {
        $previousKeyTokens = @($previousState.publicKeyFingerprints | ForEach-Object { Get-Sha256FingerprintToken -Fingerprint ([string]$_) } | Sort-Object -Unique)
        $newKeyTokens = @($keyResult.Fingerprints | ForEach-Object { Get-Sha256FingerprintToken -Fingerprint ([string]$_) } | Sort-Object -Unique)
        $preserveKeyOnly = $previousKeyTokens.Count -eq $newKeyTokens.Count -and @(Compare-Object $previousKeyTokens $newKeyTokens).Count -eq 0
    }
    $previousAuthenticationMode = if ($preserveKeyOnly) { 'key-only' } else { 'bootstrap-password' }
    $state = [pscustomobject][ordered]@{
        schemaVersion = 1
        machineFingerprint = $machineFingerprint
        preparedUtc = [DateTime]::UtcNow.ToString('o')
        targetUser = $TargetUser
        targetSid = $accountInfo.Account.SID.Value
        targetIsAdministrator = $accountInfo.IsAdministrator
        sshPort = [int]$config.access.ssh.port
        publicKeyFingerprint = $keyResult.Fingerprints[0]
        publicKeyFingerprints = @($keyResult.Fingerprints)
        approvedKeyCount = [int]$keyResult.KeyCount
        authorizedKeysBackup = $keyResult.BackupPath
        authorizedKeysPath = $keyTarget.Path
        tailscaleInstalledByRun = if ($previousProperties -contains 'tailscaleInstalledByRun') { [bool]$previousState.tailscaleInstalledByRun } else { $false }
        opensshInstalledByRun = if ($previousProperties -contains 'opensshInstalledByRun') { [bool]$previousState.opensshInstalledByRun } else { (-not $preexistingSshd) }
        defaultFirewallRuleWasEnabled = if ($previousProperties -contains 'defaultFirewallRuleWasEnabled') { [bool]$previousState.defaultFirewallRuleWasEnabled } else { $defaultRuleWasEnabled }
        sshdConfigSha256Before = if (Test-Path -LiteralPath $sshdConfig) { (Get-FileHash -LiteralPath $sshdConfig -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        authenticationMode = $previousAuthenticationMode
        authenticationModeBeforeDisable = if ($previousAuthenticationMode -eq 'key-only') { 'key-only' } else { $null }
        status = 'prepared'
    }
    Write-EnvoyStateFile -Value $state -Path $statePath -Depth 8
    Write-Output "Prepared with sshd stopped and the broad installer firewall rule disabled. State: $statePath"
    if ($previousRequestedMode -eq 'key-only' -and -not $preserveKeyOnly) { Write-Output 'The approved key set changed, so the next enable will restore bootstrap-password mode until the new key completes a signed second-device proof.' }
    Write-Output 'Next: enroll Tailscale interactively, require MFA/device approval, install the reviewed tailnet policy, then run AccessEnable.'
    return
}

if (-not (Test-Path -LiteralPath $statePath)) { throw 'No access preparation state exists. Run AccessPrepare first.' }
if (-not (Test-ExactPrivilegedFileAcl -Path $statePath)) { throw 'Access state file ACL/owner is not the exact protected policy; refusing to trust lifecycle state.' }
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
Assert-AccessStateBinding -StateObject $state -MachineFingerprint $machineFingerprint -ExpectedUser $TargetUser -ExpectedSid $accountInfo.Account.SID.Value -ExpectedPort ([int]$config.access.ssh.port) -ExpectedAdministrator ([int][bool]$accountInfo.IsAdministrator)
Assert-SshConfigurationAuthority -DirectoryPath $sshConfigDirectory -ConfigPath $sshdConfig

if ($Stage -eq 'Enable') {
    if ($state.status -notin @('prepared', 'disabled-break-glass')) {
        throw "Enable requires prepared or locally disabled state; current state is '$($state.status)'."
    }
    if (-not $config.access.overlay.unattended -or -not $config.access.overlay.requireMfa -or -not $config.access.overlay.requireDeviceApproval) {
        throw 'The reviewed configuration must require unattended host mode, MFA, and device approval.'
    }
    if (-not $AcknowledgeTailnetControls) { throw 'Pass -AcknowledgeTailnetControls only after MFA/passkey, device approval, default-deny tailnet policy, unattended host mode, no Taildrive app grants, and disabled Taildrop/Send Files are configured and reviewed.' }
    Assert-SshdServiceIdentity -ExpectedExecutable $sshdExe | Out-Null
    if ((Get-Service sshd -ErrorAction Stop).Status -eq 'Running') { throw 'sshd is unexpectedly running in a prepared/disabled state. Stop and investigate it locally before EnvoyNode activation.' }
    $preparedVerification = & (Join-Path $PSScriptRoot 'Test-EnvoyNode.ps1') -ConfigPath $ConfigPath -PassThru -NoReport
    $preparedKeyChecks = @($preparedVerification.checks | Where-Object { $_.id -in @('ssh-key-allowlist', 'access-state-integrity') -and $_.status -ne 'PASS' })
    if ($preparedKeyChecks.Count -gt 0) { throw 'The prepared authorized-key allowlist or privileged state ACL drifted. Re-run AccessPrepare locally before enabling SSH.' }
    $network = Get-TailscaleNetwork
    Assert-TailscaleHostKeyExpiry -Status $network.Status -Policy ([string]$config.access.overlay.hostKeyExpiry)
    $audit = & (Join-Path $PSScriptRoot 'Get-EnvoyAudit.ps1') -AdditionalSensitivePorts @([int]$config.access.ssh.port) -PassThru -NoReport
    if (-not $audit.access.portProxyInspectionComplete -or $audit.access.localPortProxyConfigured) { throw 'Windows port-proxy inspection is incomplete or a port-proxy rule exists. Refusing to enable SSH until the forwarding path is removed and re-audited.' }
    if (-not $audit.access.firewallInspectionComplete) { throw 'The elevated firewall inspection was incomplete. Refusing to enable SSH.' }
    if (-not $audit.access.firewallProfilesSecure) { throw 'All Windows Firewall profiles must be enabled with default inbound blocking before SSH can start.' }
    if (-not $audit.access.listenerInspectionComplete) { throw 'TCP/UDP listener inspection is incomplete. Refusing to enable SSH.' }
    if (@($audit.access.sensitiveListeners | Where-Object { $_.LocalPort -eq [int]$config.access.ssh.port }).Count -gt 0) { throw 'The configured SSH port already has a TCP or UDP endpoint. Resolve the collision before activation.' }
    if ($audit.host.pendingReboot) { throw 'Windows has a pending reboot. Complete it and re-run the plan before enabling SSH.' }
    if (-not $audit.security.uacInspectionComplete -or -not $audit.security.uacEnabled -or -not $audit.security.secureBootInspectionComplete -or -not $audit.security.secureBootEnabled) { throw 'UAC and Secure Boot must both be verified enabled before SSH activation.' }
    $unexpectedRules = @($audit.access.sensitiveFirewallRules | Where-Object {
        $_.Port -eq [int]$config.access.ssh.port -and $_.Enabled -eq 'True' -and $_.Action -in @('Allow', 'Block') -and
        $_.Name -notin $ownedRuleNames -and
        (Test-FirewallRecordAppliesToProgram -Record $_ -ProgramPath $sshdExe -ServiceName 'sshd')
    })
    if ($unexpectedRules.Count -gt 0) { throw 'An unexpected enabled SSH allow/block rule exists. Review it manually; EnvoyNode will not assume both reachability and tailnet-only exposure.' }
    $backupDir = Join-Path $stateDir ('access-backup-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    Protect-EnvoyStateDirectory -Path $backupDir
    $configExistedBefore = Test-Path -LiteralPath $sshdConfig
    if ($configExistedBefore) { Copy-EnvoyStateFile -Source $sshdConfig -Destination (Join-Path $backupDir 'sshd_config') }
    Copy-EnvoyStateFile -Source $statePath -Destination (Join-Path $backupDir 'access-current.json')
    $serviceBefore = Get-Service sshd -ErrorAction Stop
    $serviceCimBefore = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
    $serviceWasRunning = $serviceBefore.Status -eq 'Running'
    $serviceStartMode = [string]$serviceCimBefore.StartMode
    $clientProofChallenge = $null
    $reenableKeyOnly = [bool](
        ($state.PSObject.Properties.Name -contains 'authenticationModeBeforeDisable' -and $state.authenticationModeBeforeDisable -eq 'key-only') -or
        ($state.PSObject.Properties.Name -contains 'authenticationMode' -and $state.authenticationMode -eq 'key-only'))
    $block = Get-ManagedSshBlock -Config $config -UserName $TargetUser -Hardened $reenableKeyOnly -AuthorizedKeysPath ([string]$state.authorizedKeysPath)
    $hostFingerprint = $null
    try {
        $state.status = 'enable-in-progress'
        Set-StateProperty -StateObject $state -Name 'tailscaleIPv4' -Value $network.IPv4
        Set-StateProperty -StateObject $state -Name 'tailscaleIPv6' -Value $network.IPv6
        Set-StateProperty -StateObject $state -Name 'tailscaleAdapter' -Value $network.Adapter.Name
        Write-EnvoyStateFile -Value $state -Path $statePath -Depth 8
        Set-ManagedSshBlock -ConfigPathOnHost $sshdConfig -Block $block
        Protect-SshConfigurationFile -DirectoryPath $sshConfigDirectory -ConfigPath $sshdConfig
        Assert-NoUnsafeUnmanagedSshDirectives -ConfigPathOnHost $sshdConfig
        Invoke-NativeChecked -FilePath $sshdExe -ArgumentList @('-t', '-f', $sshdConfig) | Out-Null
        Assert-EffectiveSshConfiguration -Executable $sshdExe -ConfigPathOnHost $sshdConfig -Config $config -UserName $TargetUser -Hardened $reenableKeyOnly -AuthorizedKeysPath ([string]$state.authorizedKeysPath) -SourceAddress '100.64.0.1' -LocalAddress $network.IPv4 | Out-Null
        foreach ($name in $ownedRuleNames) { $null = Get-EnvoyFirewallRule -Name $name }
        Remove-EnvoyFirewallRules -Names $ownedRuleNames
        Disable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -Name $ownedRuleNames[0] -DisplayName 'EnvoyNode SSH via Tailscale IPv4' -Group 'EnvoyNode' -Direction Inbound -Action Allow -Protocol TCP -LocalPort ([int]$config.access.ssh.port) -LocalAddress $network.IPv4 -RemoteAddress '100.64.0.0/10' -InterfaceAlias $network.Adapter.Name -Profile Any -Program $sshdExe | Out-Null
        if ($network.IPv6) {
            New-NetFirewallRule -Name $ownedRuleNames[1] -DisplayName 'EnvoyNode SSH via Tailscale IPv6' -Group 'EnvoyNode' -Direction Inbound -Action Allow -Protocol TCP -LocalPort ([int]$config.access.ssh.port) -LocalAddress $network.IPv6 -RemoteAddress 'fd7a:115c:a1e0::/48' -InterfaceAlias $network.Adapter.Name -Profile Any -Program $sshdExe | Out-Null
        }
        $preStartVerification = & (Join-Path $PSScriptRoot 'Test-EnvoyNode.ps1') -ConfigPath $ConfigPath -PassThru -NoReport
        Assert-VerificationChecks -Verification $preStartVerification -RequiredIds @('managed-device-policy', 'defender', 'uac', 'secure-boot', 'drive-encryption', 'no-windows-portproxy', 'managed-port-firewall-scope', 'windows-firewall-profiles', 'tailscale-online', 'tailscale-forwarding-empty', 'tailscale-node-key-expiry', 'tailscale-adapter-binding', 'sshd-service-identity', 'ssh-tailnet-firewall', 'global-managed-port-exposure')
        Set-Service sshd -StartupType Manual
        Start-Service sshd
        Assert-SshdServiceIdentity -ExpectedExecutable $sshdExe -RequireRunning | Out-Null
        Assert-SshdListenerOwnership -Port ([int]$config.access.ssh.port) -TailscaleIPv4 $network.IPv4 -TailscaleIPv6 $network.IPv6
        $test = Test-NetConnection -ComputerName $network.IPv4 -Port ([int]$config.access.ssh.port) -WarningAction SilentlyContinue
        if (-not $test.TcpTestSucceeded) { throw 'Local SSH handshake test failed.' }
        $hostKey = Join-Path $env:ProgramData 'ssh\ssh_host_ed25519_key.pub'
        $hostFingerprint = Invoke-NativeChecked -FilePath $script:SshKeygenExe -ArgumentList @('-lf', $hostKey)
        $state.status = if ($reenableKeyOnly) { 'hardened-key-only' } else { 'enabled-awaiting-client-proof' }
        $nextAuthenticationMode = if ($reenableKeyOnly) { 'key-only' } else { 'bootstrap-password' }
        Set-StateProperty -StateObject $state -Name 'authenticationMode' -Value $nextAuthenticationMode
        Set-StateProperty -StateObject $state -Name 'enabledUtc' -Value ([DateTime]::UtcNow.ToString('o'))
        Set-StateProperty -StateObject $state -Name 'backupDirectory' -Value $backupDir
        Set-StateProperty -StateObject $state -Name 'tailscaleIPv4' -Value $network.IPv4
        Set-StateProperty -StateObject $state -Name 'tailscaleIPv6' -Value $network.IPv6
        Set-StateProperty -StateObject $state -Name 'tailscaleAdapter' -Value $network.Adapter.Name
        Set-StateProperty -StateObject $state -Name 'hostKeyFingerprint' -Value $hostFingerprint
        Set-StateProperty -StateObject $state -Name 'tailnetControlsAcknowledged' -Value $true
        $clientProofChallenge = New-ClientProofChallenge
        Set-StateProperty -StateObject $state -Name 'clientProofChallenge' -Value $clientProofChallenge
        Set-StateProperty -StateObject $state -Name 'clientProofChallengeCreatedUtc' -Value ([DateTime]::UtcNow.ToString('o'))
        foreach ($staleProofField in @('rebootProofAcceptedUtc', 'rebootProofGeneratedUtc', 'rebootProofBootUtc', 'rebootProofSigningKeyFingerprintToken', 'rebootProofHostEventRecordId', 'rebootProofHostEventUtc', 'rebootProofSourceAddress', 'proofMethod')) {
            if ($state.PSObject.Properties.Name -contains $staleProofField) { $state.PSObject.Properties.Remove($staleProofField) }
        }
        Write-EnvoyStateFile -Value $state -Path $statePath -Depth 8
        Set-Service sshd -StartupType Automatic
        $postStartAudit = & (Join-Path $PSScriptRoot 'Get-EnvoyAudit.ps1') -AdditionalSensitivePorts @([int]$config.access.ssh.port) -PassThru -NoReport
        $postCompeting = @($postStartAudit.access.sensitiveFirewallRules | Where-Object {
            $_.Port -eq [int]$config.access.ssh.port -and $_.Enabled -eq 'True' -and $_.Action -in @('Allow', 'Block') -and $_.Name -notin $ownedRuleNames
        })
        if (-not $postStartAudit.access.firewallInspectionComplete -or $postCompeting.Count -gt 0) { throw 'Post-start ActiveStore inspection found an unexpected SSH allow/block rule or was incomplete.' }
        $postStartVerification = & (Join-Path $PSScriptRoot 'Test-EnvoyNode.ps1') -ConfigPath $ConfigPath -PassThru -NoReport
        Assert-VerificationChecks -Verification $postStartVerification -RequiredIds @('managed-device-policy', 'defender', 'uac', 'secure-boot', 'drive-encryption', 'no-windows-portproxy', 'managed-port-firewall-scope', 'windows-firewall-profiles', 'tailscale-online', 'tailscale-forwarding-empty', 'tailscale-node-key-expiry', 'tailscale-adapter-binding', 'sshd-running', 'sshd-service-identity', 'ssh-listener-ownership', 'ssh-tailnet-firewall', 'global-managed-port-exposure')
    }
    catch {
        $activationError = $_
        $rollbackErrors = New-Object System.Collections.Generic.List[string]
        try { Set-Service sshd -StartupType Disabled -ErrorAction Stop } catch { $rollbackErrors.Add("service startup: $($_.Exception.Message)") }
        try { Stop-Service sshd -Force -ErrorAction Stop } catch { $rollbackErrors.Add("service stop: $($_.Exception.Message)") }
        try { Disable-EnvoyFirewallRules -Names $ownedRuleNames } catch { $rollbackErrors.Add("managed firewall disable: $($_.Exception.Message)") }
        try { Disable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore -ErrorAction Stop | Out-Null } catch {
            if (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue) { $rollbackErrors.Add("default firewall disable: $($_.Exception.Message)") }
        }
        try { Remove-EnvoyFirewallRules -Names $ownedRuleNames } catch { $rollbackErrors.Add("managed firewall removal: $($_.Exception.Message)") }
        $backup = Join-Path $backupDir 'sshd_config'
        if ($configExistedBefore -and (Test-Path -LiteralPath $backup)) {
            try {
                Copy-Item -LiteralPath $backup -Destination $sshdConfig -Force
                Protect-SshConfigurationFile -DirectoryPath $sshConfigDirectory -ConfigPath $sshdConfig
            }
            catch { $rollbackErrors.Add("configuration restore: $($_.Exception.Message)") }
        }
        elseif (-not $configExistedBefore -and (Test-Path -LiteralPath $sshdConfig)) {
            try { Remove-Item -LiteralPath $sshdConfig -Force } catch { $rollbackErrors.Add("configuration cleanup: $($_.Exception.Message)") }
        }
        $stateBackup = Join-Path $backupDir 'access-current.json'
        if (Test-Path -LiteralPath $stateBackup) {
            try { Copy-EnvoyStateFile -Source $stateBackup -Destination $statePath -Force } catch { $rollbackErrors.Add("state restore: $($_.Exception.Message)") }
        }
        try { Assert-SshAccessFailedClosed -OwnedRuleNames $ownedRuleNames -Port ([int]$config.access.ssh.port) }
        catch { throw "SSH activation failed and fail-close could not be proven. Use the local console immediately. Original: $($activationError.Exception.Message) Fail-close: $($_.Exception.Message) Rollback: $($rollbackErrors -join '; ')" }
        if ($rollbackErrors.Count -gt 0) { throw "SSH activation failed; managed SSH is proven closed, but some non-exposure rollback work requires local review. Original: $($activationError.Exception.Message) Rollback: $($rollbackErrors -join '; ')" }
        throw "SSH activation failed closed; sshd is Stopped/Disabled, protected ingress is off, no managed-port listener remains, and prior files/state were restored: $($activationError.Exception.Message)"
    }
    Write-Output "SSH is reachable only through the Tailscale adapter at $($network.IPv4)."
    Write-Output "Host key: $hostFingerprint"
    Write-Output "Client proof challenge: $clientProofChallenge"
    if ($reenableKeyOnly) { Write-Output 'The previously hardened key-only authentication mode was preserved during re-enable.' }
    else { Write-Output 'Password authentication remains temporarily enabled. Prove public-key access from the second laptop, then run AccessHarden.' }
    return
}

if ($Stage -eq 'Harden') {
    if ($state.status -ne 'enabled-awaiting-client-proof') { throw "Harden requires enabled-awaiting-client-proof state; current state is '$($state.status)'." }
    if ([string]::IsNullOrWhiteSpace($ClientProofPath) -or -not (Test-Path -LiteralPath $ClientProofPath)) { throw 'A client proof JSON file is required.' }
    $proof = Get-Content -LiteralPath $ClientProofPath -Raw | ConvertFrom-Json
    $enabledTime = [DateTime]::Parse([string]$state.enabledUtc).ToUniversalTime()
    $validatedProof = Assert-SignedClientProof -Proof $proof -StateObject $state -Config $config -ExpectedUser $TargetUser -MinimumUtc $enabledTime.AddMinutes(-2) -StateDirectory $stateDir
    $backupPath = $sshdConfig + '.pre-harden-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    Copy-Item -LiteralPath $sshdConfig -Destination $backupPath
    $stateBackupPath = $statePath + '.pre-harden-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    Copy-EnvoyStateFile -Source $statePath -Destination $stateBackupPath
    $preHardenService = Get-Service sshd -ErrorAction Stop
    $preHardenServiceCim = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
    Assert-SshdServiceIdentity -ExpectedExecutable $sshdExe -RequireRunning | Out-Null
    $preHardenWasRunning = $preHardenService.Status -eq 'Running'
    $preHardenStartMode = [string]$preHardenServiceCim.StartMode
    if (-not $preHardenWasRunning -or $preHardenStartMode -notin @('Auto', 'Automatic')) { throw 'Harden requires sshd to be Running with Automatic startup; resolve service drift and review a fresh plan.' }
    $block = Get-ManagedSshBlock -Config $config -UserName $TargetUser -Hardened $true -AuthorizedKeysPath ([string]$state.authorizedKeysPath)
    try {
        Set-ManagedSshBlock -ConfigPathOnHost $sshdConfig -Block $block
        Protect-SshConfigurationFile -DirectoryPath $sshConfigDirectory -ConfigPath $sshdConfig
        Assert-NoUnsafeUnmanagedSshDirectives -ConfigPathOnHost $sshdConfig
        Invoke-NativeChecked -FilePath $sshdExe -ArgumentList @('-t', '-f', $sshdConfig) | Out-Null
        Assert-EffectiveSshConfiguration -Executable $sshdExe -ConfigPathOnHost $sshdConfig -Config $config -UserName $TargetUser -Hardened $true -AuthorizedKeysPath ([string]$state.authorizedKeysPath) -SourceAddress ([string]$validatedProof.Payload.sourceAddress) -LocalAddress ([string]$state.tailscaleIPv4) | Out-Null
        Restart-Service sshd
        Assert-SshdServiceIdentity -ExpectedExecutable $sshdExe -RequireRunning | Out-Null
        Assert-SshdListenerOwnership -Port ([int]$config.access.ssh.port) -TailscaleIPv4 ([string]$state.tailscaleIPv4) -TailscaleIPv6 ([string]$state.tailscaleIPv6)
        $postHardenVerification = & (Join-Path $PSScriptRoot 'Test-EnvoyNode.ps1') -ConfigPath $ConfigPath -PassThru -NoReport
        Assert-VerificationChecks -Verification $postHardenVerification -RequiredIds @('managed-device-policy', 'defender', 'uac', 'secure-boot', 'drive-encryption', 'no-windows-portproxy', 'managed-port-firewall-scope', 'windows-firewall-profiles', 'tailscale-online', 'tailscale-forwarding-empty', 'tailscale-node-key-expiry', 'tailscale-adapter-binding', 'sshd-running', 'sshd-service-identity', 'ssh-listener-ownership', 'ssh-tailnet-firewall', 'global-managed-port-exposure')
        $state.status = 'hardened-key-only'
        Set-StateProperty -StateObject $state -Name 'authenticationMode' -Value 'key-only'
        Set-StateProperty -StateObject $state -Name 'authenticationModeBeforeDisable' -Value 'key-only'
        Set-StateProperty -StateObject $state -Name 'hardenedUtc' -Value ([DateTime]::UtcNow.ToString('o'))
        Set-StateProperty -StateObject $state -Name 'initialProofGeneratedUtc' -Value $validatedProof.GeneratedUtc.ToString('o')
        Set-StateProperty -StateObject $state -Name 'initialProofSigningKeyFingerprintToken' -Value $validatedProof.SigningKeyFingerprintToken
        Set-StateProperty -StateObject $state -Name 'initialProofHostEventRecordId' -Value $validatedProof.HostEventRecordId
        Set-StateProperty -StateObject $state -Name 'initialProofHostEventUtc' -Value $validatedProof.HostEventUtc.ToString('o')
        Set-StateProperty -StateObject $state -Name 'initialProofSourceAddress' -Value ([string]$validatedProof.Payload.sourceAddress)
        Set-StateProperty -StateObject $state -Name 'proofMethod' -Value 'v2-signed-host-observed'
        $postRebootChallenge = New-ClientProofChallenge
        Set-StateProperty -StateObject $state -Name 'clientProofChallenge' -Value $postRebootChallenge
        Set-StateProperty -StateObject $state -Name 'clientProofChallengeCreatedUtc' -Value ([DateTime]::UtcNow.ToString('o'))
        Set-StateProperty -StateObject $state -Name 'preHardenBackup' -Value $backupPath
        Write-EnvoyStateFile -Value $state -Path $statePath -Depth 8
    }
    catch {
        $hardeningError = $_
        try {
            Copy-Item -LiteralPath $backupPath -Destination $sshdConfig -Force
            Protect-SshConfigurationFile -DirectoryPath $sshConfigDirectory -ConfigPath $sshdConfig
            Copy-EnvoyStateFile -Source $stateBackupPath -Destination $statePath -Force
            Restore-SshdServiceState -WasRunning $preHardenWasRunning -StartMode $preHardenStartMode
            Assert-SshdServiceIdentity -ExpectedExecutable $sshdExe -RequireRunning:$preHardenWasRunning | Out-Null
            Assert-NoUnsafeUnmanagedSshDirectives -ConfigPathOnHost $sshdConfig
            Assert-EffectiveSshConfiguration -Executable $sshdExe -ConfigPathOnHost $sshdConfig -Config $config -UserName $TargetUser -Hardened $false -AuthorizedKeysPath ([string]$state.authorizedKeysPath) -SourceAddress ([string]$validatedProof.Payload.sourceAddress) -LocalAddress ([string]$state.tailscaleIPv4) | Out-Null
            if ($preHardenWasRunning) { Assert-SshdListenerOwnership -Port ([int]$config.access.ssh.port) -TailscaleIPv4 ([string]$state.tailscaleIPv4) -TailscaleIPv6 ([string]$state.tailscaleIPv6) }
            $recoveryVerification = & (Join-Path $PSScriptRoot 'Test-EnvoyNode.ps1') -ConfigPath $ConfigPath -PassThru -NoReport
            Assert-VerificationChecks -Verification $recoveryVerification -RequiredIds @('managed-device-policy', 'defender', 'uac', 'secure-boot', 'drive-encryption', 'no-windows-portproxy', 'managed-port-firewall-scope', 'windows-firewall-profiles', 'tailscale-online', 'tailscale-forwarding-empty', 'tailscale-node-key-expiry', 'tailscale-adapter-binding', 'sshd-running', 'sshd-service-identity', 'ssh-listener-ownership', 'ssh-tailnet-firewall', 'global-managed-port-exposure')
        }
        catch {
            $recoveryError = $_
            try { Disable-EnvoyFirewallRules -Names $ownedRuleNames } catch { }
            Disable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Out-Null
            Set-Service sshd -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service sshd -Force -ErrorAction SilentlyContinue
            try { Assert-SshAccessFailedClosed -OwnedRuleNames $ownedRuleNames -Port ([int]$config.access.ssh.port) }
            catch { throw "SSH hardening failed, bootstrap recovery was unsafe, and fail-close could not be proven. Use the local console immediately. Original: $($hardeningError.Exception.Message) Recovery: $($recoveryError.Exception.Message) Fail-close: $($_.Exception.Message)" }
            throw "SSH hardening failed and the exact bootstrap recovery posture could not be proven. Managed SSH was proven Stopped/Disabled with protected ingress off and no managed-port listener. Use the local console. Original: $($hardeningError.Exception.Message) Recovery: $($recoveryError.Exception.Message)"
        }
        throw "SSH hardening failed; the prior bootstrap configuration, state, service startup, and listener were restored and verified: $($hardeningError.Exception.Message)"
    }
    Write-Output 'SSH is now key-only and remains scoped to the Tailscale adapter.'
    Write-Output "Post-reboot proof challenge: $postRebootChallenge"
    return
}

if ($Stage -eq 'RebootProof') {
    if ($state.status -ne 'hardened-key-only' -or $state.authenticationMode -ne 'key-only') { throw 'RebootProof requires the hardened key-only state.' }
    if ([string]::IsNullOrWhiteSpace($ClientProofPath) -or -not (Test-Path -LiteralPath $ClientProofPath)) { throw 'A fresh post-reboot client proof JSON file is required.' }
    $proof = Get-Content -LiteralPath $ClientProofPath -Raw | ConvertFrom-Json
    $bootTime = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime()
    if ($state.PSObject.Properties.Name -notcontains 'enabledUtc') { throw 'Access state lacks the most recent enable timestamp; re-prepare locally before accepting reboot proof.' }
    $enabledTime = [DateTime]::Parse([string]$state.enabledUtc).ToUniversalTime()
    $proofReferenceTime = $enabledTime
    if ($state.PSObject.Properties.Name -contains 'hardenedUtc' -and -not [string]::IsNullOrWhiteSpace([string]$state.hardenedUtc)) {
        $hardenedTime = [DateTime]::Parse([string]$state.hardenedUtc).ToUniversalTime()
        if ($hardenedTime -gt $proofReferenceTime) { $proofReferenceTime = $hardenedTime }
    }
    if ($bootTime -le $proofReferenceTime) { throw 'Windows has not rebooted since the most recent SSH enable/hardening action. Reboot deliberately with local recovery available, then generate a new client proof.' }
    $validatedProof = Assert-SignedClientProof -Proof $proof -StateObject $state -Config $config -ExpectedUser $TargetUser -MinimumUtc $bootTime -StateDirectory $stateDir
    $proofTime = $validatedProof.GeneratedUtc
    try {
        $network = Get-TailscaleNetwork
        Assert-TailscaleHostKeyExpiry -Status $network.Status -Policy ([string]$config.access.overlay.hostKeyExpiry)
        if ((Get-Service sshd -ErrorAction Stop).Status -ne 'Running' -or (Get-Service sshd).StartType -ne 'Automatic') { throw 'sshd did not recover automatically after reboot.' }
        Assert-SshdServiceIdentity -ExpectedExecutable $sshdExe -RequireRunning | Out-Null
        Assert-NoUnsafeUnmanagedSshDirectives -ConfigPathOnHost $sshdConfig
        Assert-EffectiveSshConfiguration -Executable $sshdExe -ConfigPathOnHost $sshdConfig -Config $config -UserName $TargetUser -Hardened $true -AuthorizedKeysPath ([string]$state.authorizedKeysPath) -SourceAddress ([string]$validatedProof.Payload.sourceAddress) -LocalAddress $network.IPv4 | Out-Null
        Assert-SshdListenerOwnership -Port ([int]$config.access.ssh.port) -TailscaleIPv4 $network.IPv4 -TailscaleIPv6 $network.IPv6
        $rebootVerification = & (Join-Path $PSScriptRoot 'Test-EnvoyNode.ps1') -ConfigPath $ConfigPath -PassThru -NoReport
        Assert-VerificationChecks -Verification $rebootVerification -RequiredIds @('managed-device-policy', 'defender', 'uac', 'secure-boot', 'drive-encryption', 'no-windows-portproxy', 'managed-port-firewall-scope', 'windows-firewall-profiles', 'tailscale-online', 'tailscale-forwarding-empty', 'tailscale-node-key-expiry', 'tailscale-adapter-binding', 'sshd-running', 'sshd-service-identity', 'ssh-listener-ownership', 'ssh-tailnet-firewall', 'global-managed-port-exposure')
    }
    catch {
        $proofError = $_
        try { Disable-EnvoyFirewallRules -Names $ownedRuleNames } catch { }
        Disable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Out-Null
        Set-Service sshd -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service sshd -Force -ErrorAction SilentlyContinue
        try { Assert-SshAccessFailedClosed -OwnedRuleNames $ownedRuleNames -Port ([int]$config.access.ssh.port) }
        catch { throw "Current-boot proof found safety drift and fail-close could not be proven. Use the local console immediately. Original: $($proofError.Exception.Message) Fail-close: $($_.Exception.Message)" }
        throw "Current-boot proof found safety drift. Managed SSH was proven Stopped/Disabled with protected ingress off and no managed-port listener; recover locally and review a fresh plan. $($proofError.Exception.Message)"
    }
    Set-StateProperty -StateObject $state -Name 'rebootProofAcceptedUtc' -Value ([DateTime]::UtcNow.ToString('o'))
    Set-StateProperty -StateObject $state -Name 'rebootProofGeneratedUtc' -Value $proofTime.ToString('o')
    Set-StateProperty -StateObject $state -Name 'rebootProofBootUtc' -Value $bootTime.ToString('o')
    Set-StateProperty -StateObject $state -Name 'rebootProofSigningKeyFingerprintToken' -Value $validatedProof.SigningKeyFingerprintToken
    Set-StateProperty -StateObject $state -Name 'rebootProofHostEventRecordId' -Value $validatedProof.HostEventRecordId
    Set-StateProperty -StateObject $state -Name 'rebootProofHostEventUtc' -Value $validatedProof.HostEventUtc.ToString('o')
    Set-StateProperty -StateObject $state -Name 'rebootProofSourceAddress' -Value ([string]$validatedProof.Payload.sourceAddress)
    $nextProofChallenge = New-ClientProofChallenge
    Set-StateProperty -StateObject $state -Name 'clientProofChallenge' -Value $nextProofChallenge
    Set-StateProperty -StateObject $state -Name 'clientProofChallengeCreatedUtc' -Value ([DateTime]::UtcNow.ToString('o'))
    Write-EnvoyStateFile -Value $state -Path $statePath -Depth 8
    Write-Output 'Fresh key-only SSH access, Tailscale unattended mode, service startup, effective configuration, and listener ownership are proven for the current Windows boot.'
    Write-Output "Next proof challenge (after a later reboot or access change): $nextProofChallenge"
    return
}
