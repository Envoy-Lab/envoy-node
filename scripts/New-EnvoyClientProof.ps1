[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$HostName,
    [Parameter(Mandatory = $true)][string]$TargetUser,
    [Parameter(Mandatory = $true)][string]$IdentityFile,
    [Parameter(Mandatory = $true)][string]$ExpectedHostKeyFingerprint,
    [Parameter(Mandatory = $true)][string]$Challenge,
    [int]$Port = 22,
    [string]$OutputPath = (Join-Path (Get-Location) 'envoy-client-proof.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-OpenSshClientTool {
    param([Parameter(Mandatory = $true)][string]$Name)
    $commands = @(Get-Command -Name $Name, ($Name + '.exe') -CommandType Application -ErrorAction SilentlyContinue | Sort-Object Source -Unique)
    if ($commands.Count -eq 0) { throw "Required OpenSSH client tool is not installed or discoverable: $Name" }
    return [string]$commands[0].Source
}

if (-not (Test-Path -LiteralPath $IdentityFile)) { throw "SSH identity file not found: $IdentityFile" }
if ($TargetUser -notmatch '^[A-Za-z0-9._-]+$') { throw 'Unsafe target user name.' }
if ($HostName -notmatch '^[A-Za-z0-9.:[\]-]+$' -or $HostName.StartsWith('-')) { throw 'Unsafe host name or IP address.' }
if ($Port -lt 1 -or $Port -gt 65535) { throw 'Invalid SSH port.' }
if ($ExpectedHostKeyFingerprint -notmatch '(SHA256:[A-Za-z0-9+/]+)') { throw 'Expected host fingerprint must contain a SHA256 fingerprint.' }
$expectedToken = $Matches[1]
if ($Challenge -notmatch '^[a-fA-F0-9]{64}$') { throw 'Challenge must be the 64-character value printed locally by the host.' }
$Challenge = $Challenge.ToLowerInvariant()
$sshKeyscan = Get-OpenSshClientTool -Name 'ssh-keyscan'
$sshKeygen = Get-OpenSshClientTool -Name 'ssh-keygen'
$sshClient = Get-OpenSshClientTool -Name 'ssh'

$knownHosts = [IO.Path]::GetTempFileName()
$scanFile = [IO.Path]::GetTempFileName()
$payloadFile = [IO.Path]::GetTempFileName()
$signatureFile = $payloadFile + '.sig'
$passed = $false
$errorText = $null
$actualToken = $null
$remoteIdentity = $null
$sourceAddress = $null
$serverAddress = $null
$signingKeyFingerprintToken = $null
$signedPayloadBase64 = $null
$signatureBase64 = $null
$generatedUtc = [DateTime]::UtcNow.ToString('o')
$nonce = [Guid]::NewGuid().ToString('N')

try {
    $scan = (& $sshKeyscan -T 10 -t ed25519 -p $Port $HostName 2>$null | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($scan)) { throw 'Could not retrieve the server Ed25519 host key over the private network.' }
    $scanLines = @($scan -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($scanLines.Count -eq 0) { throw 'Host-key scan returned no usable Ed25519 entries.' }
    $approvedScanLines = New-Object System.Collections.Generic.List[string]
    $scannedTokens = New-Object System.Collections.Generic.List[string]
    foreach ($scanLine in $scanLines) {
        $scanLine | Set-Content -LiteralPath $scanFile -Encoding ASCII
        $fingerprintText = (& $sshKeygen -lf $scanFile 2>&1 | Out-String).Trim()
        $lineTokens = @([regex]::Matches([string]$fingerprintText, 'SHA256:[A-Za-z0-9+/]+') | ForEach-Object { $_.Value } | Sort-Object -Unique)
        if ($LASTEXITCODE -ne 0 -or $lineTokens.Count -ne 1) { throw 'Could not calculate exactly one fingerprint for every scanned host-key entry.' }
        if ($lineTokens[0] -ne $expectedToken) { throw "Host-key mismatch. Expected $expectedToken; scanned $($lineTokens[0])." }
        $scannedTokens.Add([string]$lineTokens[0])
        if (-not $approvedScanLines.Contains([string]$scanLine)) { $approvedScanLines.Add([string]$scanLine) }
    }
    $uniqueScannedTokens = @($scannedTokens | Sort-Object -Unique)
    if ($uniqueScannedTokens.Count -ne 1 -or $uniqueScannedTokens[0] -ne $expectedToken) { throw 'The host-key scan did not resolve to exactly the reviewed Ed25519 fingerprint.' }
    $actualToken = [string]$uniqueScannedTokens[0]
    $approvedScanLines | Set-Content -LiteralPath $knownHosts -Encoding ASCII

    $common = @(
        '-p', [string]$Port,
        '-i', (Resolve-Path -LiteralPath $IdentityFile).Path,
        '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'PreferredAuthentications=publickey',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', 'ConnectTimeout=10',
        '-o', 'ConnectionAttempts=1',
        '-o', "UserKnownHostsFile=$knownHosts",
        "$TargetUser@$HostName"
    )
    $remoteScript = "[Console]::WriteLine((whoami)); [Console]::WriteLine(`$env:SSH_CONNECTION); [Console]::WriteLine('$nonce')"
    $encodedRemoteScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($remoteScript))
    $remoteOutput = @(& $sshClient @common "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand $encodedRemoteScript" 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Public-key SSH identity and nonce check failed. $($remoteOutput -join ' ')" }
    $remoteLines = @($remoteOutput | ForEach-Object { [string]$_ } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($remoteLines.Count -lt 3) { throw 'Remote proof returned an incomplete response.' }
    $remoteIdentity = $remoteLines[0]
    $sshConnection = $remoteLines[-2]
    $nonceOutput = $remoteLines[-1]
    if ($nonceOutput -ne $nonce) { throw 'Remote nonce proof failed.' }
    $identityLeaf = ($remoteIdentity -split '\\')[-1]
    if ($identityLeaf -ine $TargetUser) { throw "Remote identity '$remoteIdentity' does not match '$TargetUser'." }
    $connectionParts = @($sshConnection -split '\s+' | Where-Object { $_ })
    if ($connectionParts.Count -ne 4 -or [int]$connectionParts[3] -ne $Port) { throw 'Remote SSH_CONNECTION evidence is malformed or reports the wrong server port.' }
    $sourceAddress = $connectionParts[0]
    $serverAddress = $connectionParts[2]

    $signingFingerprint = (& $sshKeygen -lf (Resolve-Path -LiteralPath $IdentityFile).Path 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $signingFingerprint -notmatch '(SHA256:[A-Za-z0-9+/]+)') { throw 'Could not calculate the client signing-key fingerprint.' }
    $signingKeyFingerprintToken = $Matches[1]
    $generatedUtc = [DateTime]::UtcNow.ToString('o')
    $signedPayload = [pscustomobject][ordered]@{
        schemaVersion = 2
        generatedUtc = $generatedUtc
        targetUser = $TargetUser
        hostKeyFingerprint = $ExpectedHostKeyFingerprint
        scannedFingerprintToken = $actualToken
        port = $Port
        remoteIdentity = $remoteIdentity
        sourceAddress = $sourceAddress
        serverAddress = $serverAddress
        nonce = $nonce
        challenge = $Challenge
        signingKeyFingerprintToken = $signingKeyFingerprintToken
    }
    $payloadText = $signedPayload | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($payloadFile, $payloadText, (New-Object Text.UTF8Encoding($false)))
    $signOutput = (& $sshKeygen -Y sign -f (Resolve-Path -LiteralPath $IdentityFile).Path -n envoynode-client-proof $payloadFile 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $signatureFile)) { throw "Client key could not sign the host-issued challenge. $signOutput" }
    $signedPayloadBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($payloadFile))
    $signatureBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($signatureFile))
    $passed = $true
}
catch {
    $errorText = $_.Exception.Message
}
finally {
    Remove-Item -LiteralPath $knownHosts, $scanFile, $payloadFile, $signatureFile -Force -ErrorAction SilentlyContinue
}

$proof = [pscustomobject][ordered]@{
    schemaVersion = 2
    generatedUtc = $generatedUtc
    passed = $passed
    host = $HostName
    port = $Port
    targetUser = $TargetUser
    remoteIdentity = $remoteIdentity
    sourceAddress = $sourceAddress
    serverAddress = $serverAddress
    hostKeyFingerprint = $ExpectedHostKeyFingerprint
    scannedFingerprintToken = $actualToken
    nonce = $nonce
    challenge = $Challenge
    signingKeyFingerprintToken = $signingKeyFingerprintToken
    signedPayloadBase64 = $signedPayloadBase64
    signatureBase64 = $signatureBase64
    error = $errorText
}
$proof | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
$proof | ConvertTo-Json -Depth 6
if (-not $passed) { exit 1 }
