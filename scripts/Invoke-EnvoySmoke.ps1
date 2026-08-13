[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$Image = 'envoynode/core-probe:local',
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$localDockerHost = 'npipe:////./pipe/docker_engine'
$nativeProgramFiles = if ([string]::IsNullOrWhiteSpace($env:ProgramW6432)) { $env:ProgramFiles } else { $env:ProgramW6432 }
$dockerExe = Join-Path $nativeProgramFiles 'Docker\Docker\resources\bin\docker.exe'

if (-not (Test-Path -LiteralPath $dockerExe -PathType Leaf)) { throw 'The fixed Docker Desktop CLI is not installed.' }
if ((Get-AuthenticodeSignature -FilePath $dockerExe).Status -ne 'Valid') { throw 'The fixed Docker Desktop CLI does not have a valid Authenticode signature.' }

$null = & $dockerExe --host $localDockerHost info 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Docker is installed but its engine is not reachable.' }

$prior = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    $imageText = (& $dockerExe --host $localDockerHost image inspect $Image 2>&1 | Out-String).Trim()
    $imageInspectCode = $LASTEXITCODE
}
finally { $ErrorActionPreference = $prior }
if ($imageInspectCode -ne 0) {
    throw "The smoke image '$Image' is not already present. The smoke test will not pull from the network implicitly."
}
$imageData = @($imageText | ConvertFrom-Json)[0]
if ($imageData.Config.Labels.'io.envoynode.managed' -ne 'true' -or $imageData.Config.Labels.'io.envoynode.component' -ne 'core-probe' -or $imageData.Config.Labels.'io.envoynode.base-digest' -ne 'sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff') {
    throw 'The cached core-probe image does not carry the expected EnvoyNode ownership and pinned-base labels. Rebuild the reviewed compute/Containerfile first.'
}
$inspectedImageId = [string]$imageData.Id
if ($inspectedImageId -notmatch '^sha256:[a-f0-9]{64}$') { throw 'The cached core-probe image does not have a valid immutable image ID.' }

$containerName = 'envoy-smoke-' + ([Guid]::NewGuid().ToString('N').Substring(0, 12))
$pythonCode = 'import json,os,platform; print(json.dumps(dict(ok=True,platform=platform.system(),machine=platform.machine(),cpu_count=os.cpu_count())))'
$arguments = @(
    'run', '--pull=never', '--rm',
    '--name', $containerName,
    '--label', 'io.envoynode.managed=true',
    '--network', 'none',
    '--read-only',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--pids-limit', '64',
    '--memory', '256m',
    '--cpus', '1',
    '--user', '65534:65534',
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
    '--entrypoint', 'python',
    $inspectedImageId,
    '-c', $pythonCode
)

$started = [DateTime]::UtcNow
$priorErrorActionPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    $raw = (& $dockerExe --host $localDockerHost @arguments 2>&1 | Out-String).Trim()
    $exitCode = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $priorErrorActionPreference
}
$finished = [DateTime]::UtcNow

$payload = $null
if ($exitCode -eq 0) {
    try { $payload = $raw | ConvertFrom-Json } catch { }
}

$report = [pscustomobject][ordered]@{
    reportVersion = 1
    generatedUtc = $finished.ToString('o')
    test = 'isolated-container-smoke'
    passed = ($exitCode -eq 0 -and $payload -and $payload.ok)
    containerName = $containerName
    image = $Image
    imageId = $inspectedImageId
    pinnedBaseDigest = $imageData.Config.Labels.'io.envoynode.base-digest'
    constraints = @('local-engine-npipe', 'pull=never', 'immutable-image-id', 'network=none', 'read-only', 'cap-drop=ALL', 'no-new-privileges', 'memory=256m', 'cpus=1', 'auto-remove')
    durationMs = [math]::Round(($finished - $started).TotalMilliseconds)
    result = $payload
    error = if ($exitCode -ne 0) { $raw } else { $null }
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $projectRoot = Split-Path $PSScriptRoot -Parent
    $OutputPath = Join-Path $projectRoot 'reports\smoke-latest.json'
}
$directory = Split-Path $OutputPath -Parent
if ($directory -and -not (Test-Path -LiteralPath $directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8

if ($Json) {
    $report | ConvertTo-Json -Depth 8
}
elseif ($report.passed) {
    Write-Output "PASS: isolated container started and removed without network, write access, elevated capabilities, or interaction with existing workloads."
    Write-Output "Report: $OutputPath"
}
else {
    Write-Output "FAIL: isolated container smoke test failed. $raw"
}

if (-not $report.passed) { exit 1 }
exit 0
