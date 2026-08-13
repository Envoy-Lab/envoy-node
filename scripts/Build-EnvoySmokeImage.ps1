[CmdletBinding()]
param([switch]$Build)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path $PSScriptRoot -Parent
$context = Join-Path $projectRoot 'compute'
$containerfile = Join-Path $context 'Containerfile'
$nativeProgramFiles = if ([string]::IsNullOrWhiteSpace($env:ProgramW6432)) { $env:ProgramFiles } else { $env:ProgramW6432 }
$dockerExe = Join-Path $nativeProgramFiles 'Docker\Docker\resources\bin\docker.exe'
$engine = 'npipe:////./pipe/docker_engine'
$targetImage = 'envoynode/core-probe:local'
$expectedBaseDigest = 'sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff'

if (-not $Build) {
    Write-Output "Would build the pinned probe through the fixed signed Docker Desktop CLI and publish only the project-owned tag $targetImage. Re-run with -Build to perform the network-capable image build."
    return
}
if (-not (Test-Path -LiteralPath $dockerExe -PathType Leaf)) { throw 'The fixed Docker Desktop CLI is missing.' }
if ((Get-AuthenticodeSignature -FilePath $dockerExe).Status -ne 'Valid') { throw 'The fixed Docker Desktop CLI does not have a valid Authenticode signature.' }

function Get-ImageLabels {
    param([Parameter(Mandatory = $true)][string]$Reference)
    $prior = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $text = (& $dockerExe --host $engine image inspect $Reference 2>$null | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($text)) { return $null }
        $inspection = @($text | ConvertFrom-Json)
        if ($inspection.Count -ne 1) { throw "Image reference did not resolve uniquely: $Reference" }
        return $inspection[0].Config.Labels
    }
    finally { $ErrorActionPreference = $prior }
}

$existingLabels = Get-ImageLabels -Reference $targetImage
if ($null -ne $existingLabels -and
    ([string]$existingLabels.'io.envoynode.managed' -cne 'true' -or [string]$existingLabels.'io.envoynode.component' -cne 'core-probe')) {
    throw "Refusing to replace the existing non-EnvoyNode image tag $targetImage."
}

$temporaryImage = 'envoynode/core-probe:build-' + [Guid]::NewGuid().ToString('N')
try {
    & $dockerExe --host $engine build --file $containerfile --tag $temporaryImage $context
    if ($LASTEXITCODE -ne 0) { throw 'The pinned probe image build failed.' }
    $builtLabels = Get-ImageLabels -Reference $temporaryImage
    if ($null -eq $builtLabels -or [string]$builtLabels.'io.envoynode.managed' -cne 'true' -or
        [string]$builtLabels.'io.envoynode.component' -cne 'core-probe' -or
        [string]$builtLabels.'io.envoynode.base-digest' -cne $expectedBaseDigest) {
        throw 'The built image does not carry the exact EnvoyNode ownership and pinned-base labels.'
    }
    & $dockerExe --host $engine image tag $temporaryImage $targetImage
    if ($LASTEXITCODE -ne 0) { throw 'The validated image could not be assigned the EnvoyNode smoke tag.' }
    Write-Output "Built and validated $targetImage without creating a container, network, or volume."
}
finally {
    $prior = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $dockerExe --host $engine image rm $temporaryImage 2>$null | Out-Null
    }
    finally { $ErrorActionPreference = $prior }
}
