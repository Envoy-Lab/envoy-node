[CmdletBinding()]
param(
    [string]$OutputPath,
    [int[]]$AdditionalSensitivePorts = @(),
    [switch]$Json,
    [switch]$PassThru,
    [switch]$NoReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:WindowsSystemDirectory = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    Join-Path $env:WINDIR 'Sysnative'
}
else {
    Join-Path $env:WINDIR 'System32'
}
$script:WslExe = Join-Path $script:WindowsSystemDirectory 'wsl.exe'
$script:PowerCfgExe = Join-Path $script:WindowsSystemDirectory 'powercfg.exe'
$script:NetshExe = Join-Path $script:WindowsSystemDirectory 'netsh.exe'
$script:SshExe = Join-Path $script:WindowsSystemDirectory 'OpenSSH\ssh.exe'
$script:DsRegCmdExe = Join-Path $script:WindowsSystemDirectory 'dsregcmd.exe'

foreach ($requestedPort in $AdditionalSensitivePorts) {
    if ($requestedPort -lt 1 -or $requestedPort -gt 65535) { throw "Invalid additional sensitive port: $requestedPort" }
}
$sensitivePorts = @(@(22, 3389, 21118) + @($AdditionalSensitivePorts) | Sort-Object -Unique)

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-ExternalText {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @()
    )

    $prior = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $text = (& $FilePath @ArgumentList 2>&1 | Out-String)
        $code = $LASTEXITCODE
        if ($code -ne 0) { return $null }
        return (($text -replace "`0", '').Trim())
    }
    catch { return $null }
    finally { $ErrorActionPreference = $prior }
}

function Get-ShortHash {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        $digest = $sha.ComputeHash($bytes)
        return (([BitConverter]::ToString($digest) -replace '-', '').Substring(0, 16).ToLowerInvariant())
    }
    finally {
        $sha.Dispose()
    }
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

function Get-WslDistributions {
    if (-not (Test-Path -LiteralPath $script:WslExe)) { return @() }
    $raw = Invoke-ExternalText -FilePath $script:WslExe -ArgumentList @('--list', '--quiet')
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
    return @($raw -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-WslRunningInventory {
    if (-not (Test-Path -LiteralPath $script:WslExe)) {
        return [pscustomobject][ordered]@{ inspectionComplete = $false; distributions = @() }
    }
    $raw = Invoke-ExternalText -FilePath $script:WslExe -ArgumentList @('--list', '--running', '--quiet')
    if ($null -eq $raw) {
        return [pscustomobject][ordered]@{ inspectionComplete = $false; distributions = @() }
    }
    $names = if ([string]::IsNullOrWhiteSpace($raw)) { @() } else { @($raw -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    return [pscustomobject][ordered]@{ inspectionComplete = $true; distributions = @($names) }
}

function Test-PortSpecificationIncludes {
    param($Specification, [int]$Port)
    foreach ($value in @($Specification)) {
        foreach ($tokenValue in @(([string]$value) -split ',')) {
            $token = $tokenValue.Trim()
            if ($token -in @('Any', '*')) { return $true }
            if ($token -match '^([0-9]{1,5})$' -and [int]$Matches[1] -eq $Port) { return $true }
            if ($token -match '^([0-9]{1,5})\s*-\s*([0-9]{1,5})$') {
                if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }
            }
        }
    }
    return $false
}

function Get-SensitiveFirewallRules {
    $result = New-Object System.Collections.Generic.List[object]
    if (-not (Get-Command Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
        return @()
    }

    foreach ($port in $sensitivePorts) {
        try {
            $filters = @(Get-NetFirewallPortFilter -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object {
                    [string]$_.Protocol -in @('TCP', '6', 'UDP', '17', 'Any', '256') -and
                    (Test-PortSpecificationIncludes -Specification $_.LocalPort -Port $port)
                })
            foreach ($filter in $filters) {
                $rules = @(Get-NetFirewallRule -AssociatedNetFirewallPortFilter $filter -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop)
                foreach ($rule in $rules) {
                    if ($rule.Direction -ne 'Inbound') { continue }
                    $address = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
                    $interface = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
                    $interfaceType = @(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
                    $application = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
                    $serviceFilter = @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
                    $securityFilter = @(Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
                    $result.Add([pscustomobject][ordered]@{
                        Port = $port
                        Protocol = [string]$filter.Protocol
                        LocalPortSpecification = @($filter.LocalPort)
                        RemotePortSpecification = @($filter.RemotePort)
                        IcmpType = @($filter.IcmpType)
                        DynamicTarget = @($filter.DynamicTarget)
                        DynamicTransport = @($filter.DynamicTransport)
                        Name = $rule.Name
                        DisplayName = $rule.DisplayName
                        Group = [string]$rule.Group
                        Direction = [string]$rule.Direction
                        Enabled = [string]$rule.Enabled
                        Action = [string]$rule.Action
                        Profile = [string]$rule.Profile
                        PrimaryStatus = [string]$rule.PrimaryStatus
                        EnforcementStatus = @($rule.EnforcementStatus | ForEach-Object { [string]$_ })
                        EdgeTraversalPolicy = [string]$rule.EdgeTraversalPolicy
                        LooseSourceMapping = [bool]$rule.LooseSourceMapping
                        LocalOnlyMapping = [bool]$rule.LocalOnlyMapping
                        Owner = [string]$rule.Owner
                        PackageFamilyName = [string]$rule.PackageFamilyName
                        PolicyAppId = [string]$rule.PolicyAppId
                        RemoteDynamicKeywordAddresses = @($rule.RemoteDynamicKeywordAddresses)
                        PolicyStoreSource = [string]$rule.PolicyStoreSource
                        PolicyStoreSourceType = [string]$rule.PolicyStoreSourceType
                        Platforms = @($rule.Platforms)
                        LocalAddress = @($address | ForEach-Object LocalAddress)
                        RemoteAddress = @($address | ForEach-Object RemoteAddress)
                        InterfaceAlias = @($interface | ForEach-Object InterfaceAlias)
                        InterfaceType = @($interfaceType | ForEach-Object InterfaceType)
                        Program = @($application | ForEach-Object Program)
                        Package = @($application | ForEach-Object Package)
                        Service = @($serviceFilter | ForEach-Object Service)
                        Authentication = @($securityFilter | ForEach-Object Authentication)
                        Encryption = @($securityFilter | ForEach-Object Encryption)
                        LocalUser = @($securityFilter | ForEach-Object LocalUser)
                        RemoteUser = @($securityFilter | ForEach-Object RemoteUser)
                        RemoteMachine = @($securityFilter | ForEach-Object RemoteMachine)
                        OverrideBlockRules = @($securityFilter | ForEach-Object OverrideBlockRules)
                    })
                }
            }
        }
        catch {
            $result.Add([pscustomobject][ordered]@{
                Port = $port
                Name = $null
                DisplayName = $null
                Group = $null
                Direction = 'Unknown'
                Enabled = 'Unknown'
                Action = 'Unknown'
                Profile = 'Unknown'
                PrimaryStatus = 'Unknown'
                EnforcementStatus = @('Unknown')
                Protocol = 'Unknown'
                LocalPortSpecification = @()
                RemotePortSpecification = @()
                IcmpType = @()
                DynamicTarget = @()
                DynamicTransport = @()
                LocalAddress = @()
                RemoteAddress = @()
                InterfaceAlias = @()
                InterfaceType = @()
                Program = @()
                Package = @()
                Service = @()
                Authentication = @()
                Encryption = @()
                LocalUser = @()
                RemoteUser = @()
                RemoteMachine = @()
                OverrideBlockRules = @()
                PolicyStoreSource = $null
                PolicyStoreSourceType = $null
                Platforms = @()
                Error = $_.Exception.Message
            })
        }
    }
    return $result.ToArray()
}

function Get-OutboundAllowBypassRules {
    $result = New-Object System.Collections.Generic.List[object]
    if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
        throw 'Windows Firewall rule inspection is unavailable.'
    }

    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop | Where-Object {
        [string]$_.Direction -eq 'Outbound' -and [string]$_.Enabled -eq 'True' -and [string]$_.Action -eq 'Allow'
    })
    foreach ($rule in $rules) {
        $security = @(Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
        $overrideValues = @($security | ForEach-Object OverrideBlockRules)
        if (@($overrideValues | Where-Object { $_ -eq $true -or [string]$_ -eq '1' }).Count -eq 0) { continue }
        $application = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
        $service = @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
        $address = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
        $result.Add([pscustomobject][ordered]@{
            Name = [string]$rule.Name
            DisplayName = [string]$rule.DisplayName
            PolicyStoreSource = [string]$rule.PolicyStoreSource
            PolicyStoreSourceType = [string]$rule.PolicyStoreSourceType
            Program = @($application | ForEach-Object Program)
            Service = @($service | ForEach-Object Service)
            LocalAddress = @($address | ForEach-Object LocalAddress)
            RemoteAddress = @($address | ForEach-Object RemoteAddress)
            OverrideBlockRules = $overrideValues
        })
    }
    return $result.ToArray()
}

function Get-EnabledOutboundBlockRules {
    $result = New-Object System.Collections.Generic.List[object]
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop | Where-Object {
        [string]$_.Direction -eq 'Outbound' -and [string]$_.Enabled -eq 'True' -and [string]$_.Action -eq 'Block'
    })
    foreach ($rule in $rules) {
        $application = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
        $service = @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
        $address = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
        $port = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -PolicyStore ActiveStore -ErrorAction Stop)
        $result.Add([pscustomobject][ordered]@{
            Name = [string]$rule.Name
            DisplayName = [string]$rule.DisplayName
            PolicyStoreSource = [string]$rule.PolicyStoreSource
            PolicyStoreSourceType = [string]$rule.PolicyStoreSourceType
            Protocol = @($port | ForEach-Object Protocol)
            LocalPort = @($port | ForEach-Object LocalPort)
            RemotePort = @($port | ForEach-Object RemotePort)
            Program = @($application | ForEach-Object Program)
            Service = @($service | ForEach-Object Service)
            LocalAddress = @($address | ForEach-Object LocalAddress)
            RemoteAddress = @($address | ForEach-Object RemoteAddress)
        })
    }
    return $result.ToArray()
}

$isElevated = Test-IsElevated
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentSid = $identity.User.Value
$isAdminMember = $false
try {
    $adminMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
    $isAdminMember = [bool]($adminMembers | Where-Object { $_.SID.Value -eq $currentSid })
}
catch {
    $isAdminMember = $null
}

$os = Get-CimInstance Win32_OperatingSystem
$computer = Get-CimInstance Win32_ComputerSystem
$processors = @(Get-CimInstance Win32_Processor)
$video = @(Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, AdapterRAM)
$installedMemory = (Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum).Sum
$systemDisk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"
$registryVersion = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$machineGuid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction SilentlyContinue).MachineGuid

$managementInspectionComplete = $true
$domainJoined = [bool]$computer.PartOfDomain
$azureAdJoined = $false
$workplaceJoined = $false
$mdmEnrollmentPresent = $false
$managedTargetPolicyPresent = $false
$managementError = $null
try {
    if (-not (Test-Path -LiteralPath $script:DsRegCmdExe -PathType Leaf)) { throw 'dsregcmd.exe is unavailable.' }
    $dsregText = Invoke-ExternalText -FilePath $script:DsRegCmdExe -ArgumentList @('/status')
    if ([string]::IsNullOrWhiteSpace($dsregText)) { throw 'Device registration status could not be read.' }
    function Get-DsRegStatusValue {
        param([Parameter(Mandatory = $true)][string]$Name)
        $match = [regex]::Match($dsregText, '(?m)^\s*' + [regex]::Escape($Name) + '\s*:\s*(\S+)\s*$')
        if (-not $match.Success) { return $null }
        return [string]$match.Groups[1].Value
    }
    $dsregDomain = Get-DsRegStatusValue -Name 'DomainJoined'
    $dsregAzureAd = Get-DsRegStatusValue -Name 'AzureAdJoined'
    $dsregWorkplace = Get-DsRegStatusValue -Name 'WorkplaceJoined'
    if ($null -eq $dsregDomain -or $null -eq $dsregAzureAd -or $null -eq $dsregWorkplace) { throw 'Device join fields are incomplete.' }
    $domainJoined = $domainJoined -or $dsregDomain -eq 'YES'
    $azureAdJoined = $dsregAzureAd -eq 'YES'
    $workplaceJoined = $dsregWorkplace -eq 'YES'

    $enrollmentRoot = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (-not (Test-Path -LiteralPath $enrollmentRoot)) { throw 'The Windows enrollment registry could not be inspected.' }
    foreach ($enrollmentKey in @(Get-ChildItem -LiteralPath $enrollmentRoot -ErrorAction Stop)) {
        if ($enrollmentKey.PSChildName -notmatch '^[0-9a-fA-F-]{36}$') { continue }
        $properties = Get-ItemProperty -LiteralPath $enrollmentKey.PSPath -ErrorAction Stop
        $propertyNames = @($properties.PSObject.Properties.Name)
        $upn = if ($propertyNames -contains 'UPN') { [string]$properties.UPN } else { $null }
        $discoveryService = if ($propertyNames -contains 'DiscoveryServiceFullURL') { [string]$properties.DiscoveryServiceFullURL } else { $null }
        if (-not [string]::IsNullOrWhiteSpace($upn) -or -not [string]::IsNullOrWhiteSpace($discoveryService)) {
            $mdmEnrollmentPresent = $true
            break
        }
    }

    $managedPolicyPaths = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall',
        'HKLM:\SOFTWARE\Policies\OpenSSH',
        'HKLM:\SOFTWARE\Policies\RustDesk',
        'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Firewall'
    )
    $managedTargetPolicyPresent = [bool]($managedPolicyPaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1)
}
catch {
    $managementInspectionComplete = $false
    $managementError = $_.Exception.Message
}
$managedDevice = [bool]($domainJoined -or $azureAdJoined -or $workplaceJoined -or $mdmEnrollmentPresent -or $managedTargetPolicyPresent)

$capabilities = @()
if ($isElevated) {
    try {
        $capabilities = @(Get-WindowsCapability -Online -ErrorAction Stop |
            Where-Object { $_.Name -like 'OpenSSH*' } |
            Select-Object Name, State)
    }
    catch {
        $capabilities = @([pscustomobject]@{ Name = 'OpenSSH'; State = 'Unknown'; Error = $_.Exception.Message })
    }
}
else {
    $capabilities = @([pscustomobject]@{ Name = 'OpenSSH'; State = 'UnknownNeedsElevation' })
}

$sshd = Get-Service sshd -ErrorAction SilentlyContinue
$sshCommandPresent = Test-Path -LiteralPath $script:SshExe
$sshConfigPath = Join-Path $env:ProgramData 'ssh\sshd_config'
$sshConfigHash = $null
if (Test-Path -LiteralPath $sshConfigPath) {
    $sshConfigHash = (Get-FileHash -LiteralPath $sshConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

$nativeProgramFiles = if ([string]::IsNullOrWhiteSpace($env:ProgramW6432)) { $env:ProgramFiles } else { $env:ProgramW6432 }
$tailscalePath = Join-Path $nativeProgramFiles 'Tailscale\tailscale.exe'
$tailscaleInstalled = Test-Path -LiteralPath $tailscalePath
$tailscaleInstallationTrusted = $false
$tailscaleTrustError = $null
$tailscaleService = Get-Service Tailscale -ErrorAction SilentlyContinue
$tailscaleState = $null
$tailscaleOnline = $false
$tailscaleVersion = $null
$tailscaleDaemonVersion = $null
$tailscaleVersionsMatch = $false
$parsedTailscaleCliVersion = $null
$parsedTailscaleDaemonVersion = $null
$tailscaleVersionSupportsKeyExpiry = $false
$tailscaleVersionSupportsServeStatus = $false
$tailscaleVersionMeetsSecurityFloor = $false
$tailscaleIPv4 = $null
$tailscaleIPv6 = $null
$tailscalePrefsVerified = $false
$tailscaleUnattended = $false
$tailscaleUnsafeFeaturesOff = $false
$tailscaleIncomingConnectionsEnabled = $false
$tailscaleNodeKeyExpiryMode = 'unknown'
$tailscaleNodeKeyExpiryUtc = $null
$tailscaleNodeKeyExpired = $null
$tailscaleServeInspectionComplete = $false
$tailscaleServeConfigEmpty = $false
$tailscaleFunnelInspectionComplete = $false
$tailscaleFunnelConfigEmpty = $false
$tailscaleServicesInspectionComplete = $false
$tailscaleServicesConfigEmpty = $false
$tailscaleDriveInspectionComplete = $false
$tailscaleDriveSharesEmpty = $false
$tailscaleExecutableIdentity = [pscustomobject][ordered]@{
    cliPath = $null; cliSha256 = $null; cliSignerSubject = $null; cliSignerThumbprint = $null
    servicePath = $null; serviceSha256 = $null; serviceSignerSubject = $null; serviceSignerThumbprint = $null
}
if ($tailscaleInstalled) {
    try {
        $resolvedCommand = (Resolve-Path -LiteralPath $tailscalePath).Path
        $cliSignature = Get-AuthenticodeSignature -FilePath $resolvedCommand
        if ($cliSignature.Status -ne 'Valid' -or $null -eq $cliSignature.SignerCertificate) { throw 'The fixed-path Tailscale CLI signature is not valid.' }
        $tailscaleServiceCim = Get-CimInstance Win32_Service -Filter "Name='Tailscale'" -ErrorAction Stop
        $serviceCommand = [string]$tailscaleServiceCim.PathName
        if ($serviceCommand -match '^\s*"([^"]+\.exe)"') { $serviceExecutable = $Matches[1] }
        elseif ($serviceCommand -match '^\s*([^\s]+\.exe)') { $serviceExecutable = $Matches[1] }
        else { throw 'The registered Tailscale service path is malformed.' }
        if (-not (Test-Path -LiteralPath $serviceExecutable)) { throw 'The registered Tailscale service executable is missing.' }
        $resolvedService = (Resolve-Path -LiteralPath $serviceExecutable).Path
        $trustedDirectory = (Resolve-Path -LiteralPath (Split-Path $resolvedCommand -Parent)).Path.TrimEnd('\') + '\'
        if (-not $resolvedService.StartsWith($trustedDirectory, [StringComparison]::OrdinalIgnoreCase)) { throw 'The Tailscale service executable is outside the fixed trusted directory.' }
        $serviceSignature = Get-AuthenticodeSignature -FilePath $resolvedService
        if ($serviceSignature.Status -ne 'Valid' -or $null -eq $serviceSignature.SignerCertificate) { throw 'The Tailscale service executable signature is not valid.' }
        if ([string]$cliSignature.SignerCertificate.Subject -cne [string]$serviceSignature.SignerCertificate.Subject -or
            [string]$cliSignature.SignerCertificate.Thumbprint -cne [string]$serviceSignature.SignerCertificate.Thumbprint) {
            throw 'The Tailscale CLI and registered service are not signed by the same certificate.'
        }
        $tailscaleExecutableIdentity = [pscustomobject][ordered]@{
            cliPath = $resolvedCommand
            cliSha256 = (Get-FileHash -LiteralPath $resolvedCommand -Algorithm SHA256).Hash.ToLowerInvariant()
            cliSignerSubject = [string]$cliSignature.SignerCertificate.Subject
            cliSignerThumbprint = [string]$cliSignature.SignerCertificate.Thumbprint
            servicePath = $resolvedService
            serviceSha256 = (Get-FileHash -LiteralPath $resolvedService -Algorithm SHA256).Hash.ToLowerInvariant()
            serviceSignerSubject = [string]$serviceSignature.SignerCertificate.Subject
            serviceSignerThumbprint = [string]$serviceSignature.SignerCertificate.Thumbprint
        }
        $tailscalePath = $resolvedCommand
        $tailscaleInstallationTrusted = $true
    }
    catch {
        $tailscaleTrustError = $_.Exception.Message
    }
}
if ($tailscaleInstallationTrusted) {
    $tailscaleVersion = Invoke-ExternalText -FilePath $tailscalePath -ArgumentList @('version')
    if ($tailscaleVersion -match '(?m)^\s*(\d+)\.(\d+)\.(\d+)') {
        try {
            $parsedTailscaleCliVersion = [Version]::new([int]$Matches[1], [int]$Matches[2], [int]$Matches[3])
        }
        catch { }
    }
    try {
        $statusText = Invoke-ExternalText -FilePath $tailscalePath -ArgumentList @('status', '--json')
        if ($statusText) {
            $status = $statusText | ConvertFrom-Json
            $tailscaleState = $status.BackendState
            $tailscaleOnline = [bool]$status.Self.Online
            $statusProperties = @($status.PSObject.Properties.Name)
            if ('Version' -in $statusProperties -and -not [string]::IsNullOrWhiteSpace([string]$status.Version)) {
                $tailscaleDaemonVersion = [string]$status.Version
                if ($tailscaleDaemonVersion -match '^\s*(\d+)\.(\d+)\.(\d+)') {
                    try { $parsedTailscaleDaemonVersion = [Version]::new([int]$Matches[1], [int]$Matches[2], [int]$Matches[3]) } catch { }
                }
            }
            if ($null -ne $parsedTailscaleCliVersion -and $null -ne $parsedTailscaleDaemonVersion) {
                $tailscaleVersionsMatch = $parsedTailscaleCliVersion -eq $parsedTailscaleDaemonVersion
                $tailscaleVersionSupportsKeyExpiry = $tailscaleVersionsMatch -and $parsedTailscaleCliVersion -ge [Version]::new(1, 36, 0) -and $parsedTailscaleDaemonVersion -ge [Version]::new(1, 36, 0)
                $tailscaleVersionSupportsServeStatus = $tailscaleVersionsMatch -and $parsedTailscaleCliVersion -ge [Version]::new(1, 52, 0) -and $parsedTailscaleDaemonVersion -ge [Version]::new(1, 52, 0)
                $tailscaleVersionMeetsSecurityFloor = $tailscaleVersionsMatch -and $parsedTailscaleCliVersion -ge [Version]::new(1, 98, 9) -and $parsedTailscaleDaemonVersion -ge [Version]::new(1, 98, 9)
            }
            $selfProperties = @($status.Self.PSObject.Properties.Name)
            if ($selfProperties -contains 'KeyExpiry' -and -not [string]::IsNullOrWhiteSpace([string]$status.Self.KeyExpiry)) {
                try {
                    $expiry = [DateTime]::Parse([string]$status.Self.KeyExpiry).ToUniversalTime()
                    $tailscaleNodeKeyExpiryMode = 'enabled'
                    $tailscaleNodeKeyExpiryUtc = $expiry.ToString('o')
                    $tailscaleNodeKeyExpired = [bool](
                        ($selfProperties -contains 'Expired' -and [bool]$status.Self.Expired) -or
                        $expiry -le [DateTime]::UtcNow)
                }
                catch {
                    $tailscaleNodeKeyExpiryMode = 'unknown'
                }
            }
            elseif ($tailscaleOnline -and $tailscaleVersionSupportsKeyExpiry) {
                # Tailscale omits KeyExpiry from the local status object when expiry is disabled for this node.
                $tailscaleNodeKeyExpiryMode = 'disabled'
                $tailscaleNodeKeyExpired = $false
            }
            if ($tailscaleOnline) {
                $tailscaleIPv4 = Invoke-ExternalText -FilePath $tailscalePath -ArgumentList @('ip', '-4')
                $tailscaleIPv6 = Invoke-ExternalText -FilePath $tailscalePath -ArgumentList @('ip', '-6')
            }
            $prefsText = Invoke-ExternalText -FilePath $tailscalePath -ArgumentList @('debug', 'prefs')
            if ($prefsText) {
                $prefs = $prefsText | ConvertFrom-Json
                $prefNames = @($prefs.PSObject.Properties.Name)
                $requiredPrefs = @('ForceDaemon', 'RunSSH', 'RunWebClient', 'RemoteConfig', 'AdvertiseRoutes', 'ExitNodeIP', 'ShieldsUp')
                if (@($requiredPrefs | Where-Object { $_ -notin $prefNames }).Count -eq 0) {
                    $tailscalePrefsVerified = $true
                    $tailscaleUnattended = [bool]$prefs.ForceDaemon
                    $tailscaleIncomingConnectionsEnabled = -not [bool]$prefs.ShieldsUp
                    $tailscaleUnsafeFeaturesOff = [bool](
                        -not $prefs.RunSSH -and -not $prefs.RunWebClient -and -not $prefs.RemoteConfig -and
                        @($prefs.AdvertiseRoutes).Count -eq 0 -and [string]::IsNullOrWhiteSpace([string]$prefs.ExitNodeIP))
                }
            }
            if ($tailscaleVersionSupportsServeStatus) {
                $serveText = Invoke-ExternalText -FilePath $tailscalePath -ArgumentList @('serve', 'status', '--json')
                if (-not [string]::IsNullOrWhiteSpace($serveText)) {
                    try {
                        $serveStatus = $serveText | ConvertFrom-Json
                        $tailscaleServeConfigEmpty = Test-JsonTopLevelObjectEmpty -Value $serveStatus
                        $tailscaleServeInspectionComplete = $true
                    }
                    catch { }
                }
                $funnelText = Invoke-ExternalText -FilePath $tailscalePath -ArgumentList @('funnel', 'status', '--json')
                if (-not [string]::IsNullOrWhiteSpace($funnelText)) {
                    try {
                        $funnelStatus = $funnelText | ConvertFrom-Json
                        $tailscaleFunnelConfigEmpty = Test-JsonTopLevelObjectEmpty -Value $funnelStatus
                        $tailscaleFunnelInspectionComplete = $true
                    }
                    catch { }
                }
                $servicesText = Invoke-ExternalText -FilePath $tailscalePath -ArgumentList @('serve', 'get-config', '--all')
                if (-not [string]::IsNullOrWhiteSpace($servicesText)) {
                    try {
                        $servicesConfig = $servicesText | ConvertFrom-Json
                        $serviceProperties = @($servicesConfig.PSObject.Properties.Name)
                        $unknownServiceProperties = @($serviceProperties | Where-Object { $_ -notin @('version', 'services') })
                        if ('version' -in $serviceProperties -and [string]$servicesConfig.version -ceq '0.0.1' -and $unknownServiceProperties.Count -eq 0) {
                            $servicesValue = if ('services' -in $serviceProperties) { $servicesConfig.services } else { $null }
                            $tailscaleServicesConfigEmpty = Test-JsonCollectionEmptyOrNull -Value $servicesValue
                            $tailscaleServicesInspectionComplete = $true
                        }
                    }
                    catch { }
                }
                $driveText = Invoke-ExternalText -FilePath $tailscalePath -ArgumentList @('drive', 'list')
                $driveEmpty = Test-TailscaleDriveListEmpty -Text $driveText
                if ($null -ne $driveEmpty) {
                    $tailscaleDriveSharesEmpty = [bool]$driveEmpty
                    $tailscaleDriveInspectionComplete = $true
                }
            }
        }
    }
    catch {
        $tailscaleState = 'Unknown'
    }
}

$tailscaleAdapters = @()
try {
    $tailscaleAdapters = @(Get-NetAdapter -ErrorAction Stop |
        Where-Object { $_.InterfaceDescription -match 'Tailscale' } |
        Select-Object Name, InterfaceDescription, Status, ifIndex)
}
catch { }

$rdpDeny = $null
try {
    $rdpDeny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
}
catch { }
$rdpHostSupported = [bool]($os.Caption -match 'Professional|Enterprise|Education|Server')

$dockerPath = Join-Path $nativeProgramFiles 'Docker\Docker\resources\bin\docker.exe'
$dockerInstalled = Test-Path -LiteralPath $dockerPath
$dockerRunning = $false
$dockerData = $null
if ($dockerInstalled) {
    try {
        $dockerText = Invoke-ExternalText -FilePath $dockerPath -ArgumentList @('--host', 'npipe:////./pipe/docker_engine', 'info', '--format', '{{json .}}')
        if ($dockerText) {
            $dockerData = $dockerText | ConvertFrom-Json
            $dockerRunning = $true
        }
    }
    catch { }
}

$defender = $null
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $defender = [pscustomobject][ordered]@{
        AntivirusEnabled = [bool]$mp.AntivirusEnabled
        RealTimeProtectionEnabled = [bool]$mp.RealTimeProtectionEnabled
        AntispywareEnabled = [bool]$mp.AntispywareEnabled
    }
}
catch { }

$encryption = [pscustomobject][ordered]@{ Status = 'Unknown'; Protection = $null }
try {
    $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    $encryption = [pscustomobject][ordered]@{
        Status = [string]$volume.VolumeStatus
        Protection = [string]$volume.ProtectionStatus
    }
}
catch { }

$pendingReboot = [bool](
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
)
$uacInspectionComplete = $false
$uacEnabled = $false
try {
    $enableLua = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop).EnableLUA
    $uacInspectionComplete = $true
    $uacEnabled = [int]$enableLua -eq 1
}
catch { }
$secureBootInspectionComplete = $false
$secureBootEnabled = $false
try {
    $secureBootEnabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
    $secureBootInspectionComplete = $true
}
catch { }

$sleepText = Invoke-ExternalText -FilePath $script:PowerCfgExe -ArgumentList @('/query', 'SCHEME_CURRENT', 'SUB_SLEEP', 'STANDBYIDLE')
$sleepAcSeconds = $null
if ($sleepText -match 'Current AC Power Setting Index:\s+0x([0-9a-fA-F]+)') {
    $sleepAcSeconds = [Convert]::ToInt64($Matches[1], 16)
}
$hibernateText = Invoke-ExternalText -FilePath $script:PowerCfgExe -ArgumentList @('/query', 'SCHEME_CURRENT', 'SUB_SLEEP', 'HIBERNATEIDLE')
$hibernateAcSeconds = $null
if ($hibernateText -match 'Current AC Power Setting Index:\s+0x([0-9a-fA-F]+)') {
    $hibernateAcSeconds = [Convert]::ToInt64($Matches[1], 16)
}
$lidText = Invoke-ExternalText -FilePath $script:PowerCfgExe -ArgumentList @('/qh', 'SCHEME_CURRENT', 'SUB_BUTTONS', 'LIDACTION')
$lidAcAction = $null
if ($lidText -match 'Current AC Power Setting Index:\s+0x([0-9a-fA-F]+)') {
    $lidAcAction = [Convert]::ToInt32($Matches[1], 16)
}

$listeners = New-Object System.Collections.Generic.List[object]
$listenerInspectionComplete = $true
try {
    if (-not (Get-Command Get-NetTCPConnection -ErrorAction Stop)) { throw 'TCP endpoint inspection is unavailable.' }
    foreach ($listener in @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -in $sensitivePorts })) {
        $listeners.Add([pscustomobject][ordered]@{ Protocol = 'TCP'; LocalAddress = [string]$listener.LocalAddress; LocalPort = [int]$listener.LocalPort; OwningProcess = [int]$listener.OwningProcess })
    }
    if (-not (Get-Command Get-NetUDPEndpoint -ErrorAction Stop)) { throw 'UDP endpoint inspection is unavailable.' }
    foreach ($listener in @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { $_.LocalPort -in $sensitivePorts })) {
        $listeners.Add([pscustomobject][ordered]@{ Protocol = 'UDP'; LocalAddress = [string]$listener.LocalAddress; LocalPort = [int]$listener.LocalPort; OwningProcess = [int]$listener.OwningProcess })
    }
}
catch { $listenerInspectionComplete = $false }

$firewallRules = @(Get-SensitiveFirewallRules)
$firewallInspectionComplete = [bool](Get-Command Get-NetFirewallPortFilter -ErrorAction SilentlyContinue) -and
    @($firewallRules | Where-Object { $_.Enabled -eq 'Unknown' }).Count -eq 0
$outboundAllowBypassRules = @()
$outboundAllowBypassInspectionComplete = $true
try { $outboundAllowBypassRules = @(Get-OutboundAllowBypassRules) }
catch { $outboundAllowBypassInspectionComplete = $false }
$outboundBlockRules = @()
$outboundBlockInspectionComplete = $true
try { $outboundBlockRules = @(Get-EnabledOutboundBlockRules) }
catch { $outboundBlockInspectionComplete = $false }
$firewallProfiles = @()
$firewallProfileInspectionComplete = $true
try {
    $firewallProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
        [pscustomobject][ordered]@{
            Name = [string]$_.Name
            Enabled = [string]$_.Enabled
            DefaultInboundAction = [string]$_.DefaultInboundAction
            DefaultOutboundAction = [string]$_.DefaultOutboundAction
            AllowInboundRules = [string]$_.AllowInboundRules
            AllowLocalFirewallRules = [string]$_.AllowLocalFirewallRules
            DisabledInterfaceAliases = @($_.DisabledInterfaceAliases)
        }
    })
}
catch {
    $firewallProfileInspectionComplete = $false
    $firewallProfiles = @([pscustomobject][ordered]@{ Name = 'Unknown'; Enabled = 'Unknown'; DefaultInboundAction = 'Unknown'; DefaultOutboundAction = 'Unknown'; AllowInboundRules = 'Unknown'; AllowLocalFirewallRules = 'Unknown'; DisabledInterfaceAliases = @(); Error = $_.Exception.Message })
}
$firewallServices = @(@('MpsSvc', 'BFE') | ForEach-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue })
$firewallServicesSecure = [bool]($firewallServices.Count -eq 2 -and @($firewallServices | Where-Object { $_.Status -ne 'Running' -or $_.StartType -ne 'Automatic' }).Count -eq 0)
$profileNames = @($firewallProfiles.Name | Sort-Object -Unique)
$firewallProfilesSecure = [bool]($firewallProfileInspectionComplete -and $firewallServicesSecure -and $firewallProfiles.Count -eq 3 -and @(Compare-Object $profileNames @('Domain', 'Private', 'Public')).Count -eq 0 -and
    @($firewallProfiles | Where-Object {
        $_.Enabled -notin @('True', '1') -or $_.DefaultInboundAction -notin @('Block', '4') -or
        $_.AllowInboundRules -notin @('True', '1') -or $_.AllowLocalFirewallRules -notin @('True', '1') -or
        @($_.DisabledInterfaceAliases | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0
    }).Count -eq 0)
$broadFirewallRules = @($firewallRules | Where-Object {
    $_.Enabled -eq 'True' -and $_.Action -eq 'Allow' -and
    ((@($_.RemoteAddress).Count -eq 0) -or (@($_.RemoteAddress) -contains 'Any') -or (@($_.RemoteAddress) -contains '*'))
})

$portProxyDump = Invoke-ExternalText -FilePath $script:NetshExe -ArgumentList @('interface', 'portproxy', 'dump')
$portProxyInspectionComplete = $null -ne $portProxyDump
$portProxyConfigured = [bool]($portProxyInspectionComplete -and $portProxyDump -match '(?im)^\s*add\s+v(?:4|6)tov(?:4|6)\b')
$wslVersion = if (Test-Path -LiteralPath $script:WslExe) { Invoke-ExternalText -FilePath $script:WslExe -ArgumentList @('--version') } else { $null }
$wslDistributions = @(Get-WslDistributions)
$wslRunningInventory = Get-WslRunningInventory

$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding {
    param([string]$Severity, [string]$Code, [string]$Message)
    $findings.Add([pscustomobject][ordered]@{ Severity = $Severity; Code = $Code; Message = $Message })
}

if (-not $tailscaleInstalled) { Add-Finding 'WARN' 'TAILSCALE_ABSENT' 'The private overlay client is not installed.' }
elseif (-not $tailscaleInstallationTrusted) { Add-Finding 'WARN' 'TAILSCALE_INSTALLATION_UNTRUSTED' "The Tailscale installation was not executed because its fixed path, service correlation, or signature could not be trusted: $tailscaleTrustError" }
elseif (-not $tailscaleVersionMeetsSecurityFloor) { Add-Finding 'WARN' 'TAILSCALE_VERSION_TOO_OLD' 'Tailscale 1.98.9 or newer is required by the current security floor and Services/Serve/Funnel/Taildrive inspection.' }
elseif (-not $tailscaleServeInspectionComplete -or -not $tailscaleFunnelInspectionComplete -or -not $tailscaleServicesInspectionComplete -or -not $tailscaleDriveInspectionComplete) { Add-Finding 'WARN' 'TAILSCALE_EXTRA_SURFACES_UNVERIFIED' 'Persistent Tailscale Serve, Funnel, Services, or Taildrive share state could not be inspected conclusively.' }
elseif (-not $tailscaleServeConfigEmpty -or -not $tailscaleFunnelConfigEmpty -or -not $tailscaleServicesConfigEmpty -or -not $tailscaleDriveSharesEmpty) { Add-Finding 'WARN' 'TAILSCALE_EXTRA_SURFACES_CONFIGURED' 'A persistent Tailscale forward or Taildrive share exists; remote-access activation is refused.' }
elseif (-not $tailscaleOnline) { Add-Finding 'WARN' 'TAILSCALE_OFFLINE' 'Tailscale is installed but not online.' }
if (-not $sshd) { Add-Finding 'WARN' 'SSHD_ABSENT' 'Windows OpenSSH Server is not installed or registered.' }
if ($rdpHostSupported -eq $false) { Add-Finding 'INFO' 'RDP_HOME_UNSUPPORTED' 'This Windows edition cannot host Microsoft RDP; use the optional RustDesk direct-IP adapter.' }
if (-not $firewallInspectionComplete) { Add-Finding 'WARN' 'FIREWALL_INSPECTION_INCOMPLETE' 'Managed-port firewall rules could not be fully inspected in this session. Activation requires a successful elevated inspection.' }
if (-not $firewallProfilesSecure) { Add-Finding 'WARN' 'FIREWALL_PROFILE_UNSAFE_OR_UNVERIFIED' 'All active Windows Firewall profiles must be enabled with default inbound blocking before any listener is enabled.' }
if (-not $outboundAllowBypassInspectionComplete) { Add-Finding 'WARN' 'FIREWALL_ALLOW_BYPASS_UNVERIFIED' 'Outbound authenticated-bypass firewall rules could not be inspected.' }
elseif ($outboundAllowBypassRules.Count -gt 0) { Add-Finding 'WARN' 'FIREWALL_ALLOW_BYPASS_PRESENT' 'An enabled outbound Allow rule can override matching block rules; optional RustDesk activation is refused.' }
if ($broadFirewallRules.Count -gt 0) { Add-Finding 'WARN' 'BROAD_FIREWALL_RULE' 'At least one enabled allow rule on a managed port is not remote-address scoped. Review before enabling any listener.' }
if (-not $portProxyInspectionComplete) { Add-Finding 'WARN' 'PORTPROXY_INSPECTION_INCOMPLETE' 'Windows port-proxy configuration could not be inspected. Remote-access activation must fail closed.' }
elseif ($portProxyConfigured) { Add-Finding 'WARN' 'PORTPROXY_CONFIGURED' 'At least one Windows port-proxy rule exists. Remove or explicitly investigate it before remote-access activation.' }
if ($listeners.Count -gt 0) { Add-Finding 'INFO' 'EXISTING_LISTENER' 'One or more managed ports already has a listener. Preserve ownership and investigate collisions.' }
if (-not $listenerInspectionComplete) { Add-Finding 'WARN' 'LISTENER_INSPECTION_INCOMPLETE' 'TCP/UDP endpoint inspection was incomplete. Strict acceptance must fail closed.' }
if ($dockerRunning -and [int]$dockerData.ContainersRunning -gt 0) { Add-Finding 'INFO' 'DOCKER_WORKLOADS_PRESENT' 'Existing Docker workloads are running. EnvoyNode must not alter their containers, networks, volumes, or global settings.' }
if ($video | Where-Object { $_.Name -match '8050S' -and $_.AdapterRAM -le 5GB }) { Add-Finding 'WARN' 'GPU_MEMORY_LOW' 'The Radeon 8050S currently reports about 4 GB reserved graphics memory, which limits larger GPU-resident models. Changing VGM is a separate rebooting action.' }
if ($pendingReboot) { Add-Finding 'WARN' 'PENDING_REBOOT' 'Windows reports a pending reboot. Do not perform connectivity hardening until the reboot state is cleared and console access is available.' }
if (-not $uacInspectionComplete -or -not $uacEnabled) { Add-Finding 'WARN' 'UAC_DISABLED_OR_UNVERIFIED' 'User Account Control must be verified enabled before remote activation.' }
if (-not $secureBootInspectionComplete -or -not $secureBootEnabled) { Add-Finding 'WARN' 'SECURE_BOOT_DISABLED_OR_UNVERIFIED' 'Secure Boot must be verified enabled before unattended acceptance.' }
if ($sleepAcSeconds -eq 0) { Add-Finding 'INFO' 'AC_SLEEP_DISABLED' 'Plugged-in sleep is already set to Never.' }
elseif ($sleepAcSeconds -ne $null) { Add-Finding 'WARN' 'AC_SLEEP_ENABLED' 'The machine can sleep while plugged in, which interrupts remote access.' }
if ($hibernateAcSeconds -eq 0) { Add-Finding 'INFO' 'AC_HIBERNATE_DISABLED' 'Plugged-in idle hibernation is set to Never.' }
elseif ($hibernateAcSeconds -ne $null) { Add-Finding 'WARN' 'AC_HIBERNATE_ENABLED' 'The machine can hibernate while plugged in, which interrupts remote access.' }
if ($lidAcAction -eq 0) { Add-Finding 'INFO' 'AC_LID_DO_NOTHING' 'Closing the lid while plugged in is configured to do nothing.' }
elseif ($lidAcAction -ne $null) { Add-Finding 'WARN' 'AC_LID_INTERRUPTS' 'Closing the lid while plugged in is configured to sleep, hibernate, or shut down.' }
if ($encryption.Protection -notmatch 'On') { Add-Finding 'WARN' 'ENCRYPTION_UNVERIFIED' 'System-drive encryption protection could not be verified as on. Verify Device Encryption and its recovery key before 24/7 use.' }
if (-not $managementInspectionComplete) { Add-Finding 'WARN' 'DEVICE_MANAGEMENT_INSPECTION_INCOMPLETE' 'Domain, Entra ID/workplace join, MDM enrollment, and managed target-policy inspection was incomplete. Every mutation must stop.' }
elseif ($managedDevice) { Add-Finding 'WARN' 'MANAGED_DEVICE_OR_POLICY' 'The host is domain/Entra/workplace joined, MDM-enrolled, or has managed firewall/OpenSSH/RustDesk policy. EnvoyNode mutations are refused.' }

$audit = [pscustomobject][ordered]@{
    reportVersion = 1
    generatedUtc = [DateTime]::UtcNow.ToString('o')
    machineFingerprint = Get-ShortHash -Value $machineGuid
    host = [pscustomobject][ordered]@{
        osCaption = $os.Caption
        osVersion = $os.Version
        displayVersion = $registryVersion.DisplayVersion
        editionId = $registryVersion.EditionID
        build = $os.BuildNumber
        architecture = $os.OSArchitecture
        powershell = $PSVersionTable.PSVersion.ToString()
        currentUserSid = $currentSid
        elevated = $isElevated
        currentUserIsAdministratorMember = $isAdminMember
        pendingReboot = $pendingReboot
    }
    management = [pscustomobject][ordered]@{
        inspectionComplete = $managementInspectionComplete
        domainJoined = $domainJoined
        azureAdJoined = $azureAdJoined
        workplaceJoined = $workplaceJoined
        mdmEnrollmentPresent = $mdmEnrollmentPresent
        managedTargetPolicyPresent = $managedTargetPolicyPresent
        managedDeviceOrPolicy = $managedDevice
        error = $managementError
    }
    hardware = [pscustomobject][ordered]@{
        cpu = @($processors | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, VirtualizationFirmwareEnabled)
        installedMemoryGB = [math]::Round($installedMemory / 1GB, 1)
        windowsVisibleMemoryGB = [math]::Round($computer.TotalPhysicalMemory / 1GB, 1)
        gpu = @($video | ForEach-Object {
            [pscustomobject][ordered]@{
                name = $_.Name
                driverVersion = $_.DriverVersion
                reportedAdapterMemoryGB = if ($_.AdapterRAM) { [math]::Round($_.AdapterRAM / 1GB, 1) } else { $null }
            }
        })
        systemDriveFreeGB = [math]::Round($systemDisk.FreeSpace / 1GB, 1)
    }
    access = [pscustomobject][ordered]@{
        tailscale = [pscustomobject][ordered]@{
            installed = [bool]$tailscaleInstalled
            installationTrusted = [bool]$tailscaleInstallationTrusted
            executableIdentity = $tailscaleExecutableIdentity
            trustError = $tailscaleTrustError
            serviceStatus = if ($tailscaleService) { [string]$tailscaleService.Status } else { $null }
            serviceStartType = if ($tailscaleService) { [string]$tailscaleService.StartType } else { $null }
            backendState = $tailscaleState
            online = $tailscaleOnline
            version = $tailscaleVersion
            daemonVersion = $tailscaleDaemonVersion
            cliDaemonVersionsMatch = $tailscaleVersionsMatch
            versionSupportsKeyExpiry = $tailscaleVersionSupportsKeyExpiry
            versionSupportsServeStatus = $tailscaleVersionSupportsServeStatus
            versionMeetsSecurityFloor = $tailscaleVersionMeetsSecurityFloor
            ipv4 = $tailscaleIPv4
            ipv6 = $tailscaleIPv6
            preferencesVerified = $tailscalePrefsVerified
            unattendedMode = $tailscaleUnattended
            unsafeServerFeaturesOff = $tailscaleUnsafeFeaturesOff
            incomingConnectionsEnabled = $tailscaleIncomingConnectionsEnabled
            nodeKeyExpiryMode = $tailscaleNodeKeyExpiryMode
            nodeKeyExpiryUtc = $tailscaleNodeKeyExpiryUtc
            nodeKeyExpired = $tailscaleNodeKeyExpired
            serveInspectionComplete = $tailscaleServeInspectionComplete
            serveConfigEmpty = $tailscaleServeConfigEmpty
            funnelInspectionComplete = $tailscaleFunnelInspectionComplete
            funnelConfigEmpty = $tailscaleFunnelConfigEmpty
            servicesInspectionComplete = $tailscaleServicesInspectionComplete
            servicesConfigEmpty = $tailscaleServicesConfigEmpty
            driveInspectionComplete = $tailscaleDriveInspectionComplete
            driveSharesEmpty = $tailscaleDriveSharesEmpty
            adapterCount = $tailscaleAdapters.Count
            adapters = $tailscaleAdapters
        }
        openssh = [pscustomobject][ordered]@{
            clientPresent = [bool]$sshCommandPresent
            capabilities = $capabilities
            serverServicePresent = [bool]$sshd
            serverStatus = if ($sshd) { [string]$sshd.Status } else { $null }
            serverStartType = if ($sshd) { [string]$sshd.StartType } else { $null }
            configPresent = Test-Path -LiteralPath $sshConfigPath
            configSha256 = $sshConfigHash
        }
        desktop = [pscustomobject][ordered]@{
            rdpHostSupported = $rdpHostSupported
            rdpEnabled = ($rdpDeny -eq 0)
        }
        sensitiveListeners = $listeners.ToArray()
        listenerInspectionComplete = $listenerInspectionComplete
        sensitivePortsInspected = $sensitivePorts
        sensitiveFirewallRules = $firewallRules
        firewallInspectionComplete = $firewallInspectionComplete
        firewallProfiles = $firewallProfiles
        firewallProfileInspectionComplete = $firewallProfileInspectionComplete
        firewallProfilesSecure = $firewallProfilesSecure
        firewallServices = @($firewallServices | Select-Object Name, Status, StartType)
        outboundAllowBypassInspectionComplete = $outboundAllowBypassInspectionComplete
        outboundAllowBypassRules = $outboundAllowBypassRules
        outboundBlockInspectionComplete = $outboundBlockInspectionComplete
        outboundBlockRules = $outboundBlockRules
        broadFirewallRuleCount = $broadFirewallRules.Count
        portProxyInspectionComplete = $portProxyInspectionComplete
        localPortProxyConfigured = $portProxyConfigured
    }
    compute = [pscustomobject][ordered]@{
        wslInstalled = Test-Path -LiteralPath $script:WslExe
        wslVersionText = $wslVersion
        distributions = $wslDistributions
        runningDistributions = @($wslRunningInventory.distributions)
        runningDistributionInspectionComplete = [bool]$wslRunningInventory.inspectionComplete
        globalWslConfigPresent = Test-Path (Join-Path $env:USERPROFILE '.wslconfig')
        dockerInstalled = $dockerInstalled
        dockerRunning = $dockerRunning
        dockerServerVersion = if ($dockerRunning) { $dockerData.ServerVersion } else { $null }
        dockerRunningContainers = if ($dockerRunning) { [int]$dockerData.ContainersRunning } else { $null }
        dockerMemoryGB = if ($dockerRunning) { [math]::Round([double]$dockerData.MemTotal / 1GB, 1) } else { $null }
    }
    security = [pscustomobject][ordered]@{
        defender = $defender
        uacInspectionComplete = $uacInspectionComplete
        uacEnabled = $uacEnabled
        secureBootInspectionComplete = $secureBootInspectionComplete
        secureBootEnabled = $secureBootEnabled
        systemDriveEncryption = $encryption
        pluggedInSleepSeconds = $sleepAcSeconds
        pluggedInHibernateSeconds = $hibernateAcSeconds
        pluggedInLidAction = $lidAcAction
    }
    findings = $findings.ToArray()
}

if (-not $NoReport) {
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $projectRoot = Split-Path $PSScriptRoot -Parent
        $OutputPath = Join-Path $projectRoot 'reports\audit-latest.json'
    }
    $directory = Split-Path $OutputPath -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $audit | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
}

if ($PassThru) {
    return $audit
}

if ($Json) {
    $audit | ConvertTo-Json -Depth 10
}
else {
    Write-Output "EnvoyNode audit: $($audit.host.osCaption), $($audit.hardware.installedMemoryGB) GB RAM"
    Write-Output "Remote access: Tailscale installed=$($audit.access.tailscale.installed); sshd present=$($audit.access.openssh.serverServicePresent); RDP host supported=$($audit.access.desktop.rdpHostSupported)"
    Write-Output "Compute: WSL installed=$($audit.compute.wslInstalled); Docker running=$($audit.compute.dockerRunning); distros=$($audit.compute.distributions -join ', ')"
    foreach ($finding in $audit.findings) {
        Write-Output "[$($finding.Severity)] $($finding.Code): $($finding.Message)"
    }
    if (-not $NoReport) { Write-Output "Report: $OutputPath" }
}
