[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [string]$OutputPath,
    [switch]$Json,
    [switch]$PassThru,
    [switch]$NoReport,
    [switch]$SkipSmoke,
    [switch]$OfflineOnly,
    [switch]$RequireAlreadyRunning
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
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $OwnerSid -or -not $acl.AreAccessRulesProtected) { throw "Compute state owner or inheritance protection is not exact: $Path" }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $expectedSids = @($OwnerSid, 'S-1-5-18', 'S-1-5-32-544') | Sort-Object
    $actualSids = @($rules | ForEach-Object { $_.IdentityReference.Value } | Sort-Object)
    if ($rules.Count -ne 3 -or (Compare-Object $expectedSids $actualSids)) { throw "Compute state ACL principals are not exact: $Path" }
    foreach ($rule in $rules) {
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            [int]$rule.FileSystemRights -ne [int][Security.AccessControl.FileSystemRights]::FullControl) { throw "Compute state ACL contains an unexpected rule: $Path" }
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

function Get-EffectiveWslDefaultUser {
    param([Parameter(Mandatory = $true)][string]$Distribution)
    $prior = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $text = (& $script:WslExe -d $Distribution -- id -un 2>&1 | Out-String).Trim()
        $code = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $prior }
    if ($code -ne 0) { throw "Could not verify the effective WSL default user (exit $code). $text" }
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
        throw 'The EnvoyNode marker does not exactly match this machine, owner, and ready lifecycle.'
    }
    $canonical = [pscustomobject][ordered]@{ schemaVersion = 1; managedBy = 'EnvoyNode'; machineFingerprint = $script:machineFingerprint; windowsOwnerSid = $script:windowsOwnerSid; status = 'ready' } | ConvertTo-Json -Compress
    if ($JsonText.Trim() -cne $canonical) { throw 'The EnvoyNode marker is valid JSON but is not the exact canonical marker.' }
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "Configuration file not found: $ConfigPath" }
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$script:distro = [string]$config.compute.distribution
$linuxUser = [string]$config.compute.linuxUser
if ($script:distro -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { throw 'Unsafe WSL distribution name.' }
if ($script:distro -match '^docker-desktop(?:-data)?$') { throw 'The Docker Desktop distributions are protected and cannot be verified as EnvoyNode compute targets.' }
if ($linuxUser -notmatch '^[a-z_][a-z0-9_-]{0,30}$' -or $linuxUser -eq 'root') { throw 'Unsafe or privileged Linux user name.' }
$configuredWindowsOwner = [string]$config.access.ssh.targetUser
if ([string]::IsNullOrWhiteSpace($configuredWindowsOwner)) { $configuredWindowsOwner = $env:USERNAME }
if ($configuredWindowsOwner -ine $env:USERNAME) { throw "Run this verification as WSL owner '$configuredWindowsOwner'." }
if (-not (Test-WslPlatformReady)) { throw 'The WSL2 platform is not operational.' }

$existing = @(((& $script:WslExe --list --quiet 2>$null | Out-String) -replace "`0", '') -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($LASTEXITCODE -ne 0 -or $existing -notcontains $script:distro) { throw "WSL distribution not found for current Windows user: $($script:distro)" }
$registration = Get-WslRegistration -Distribution $script:distro
if (-not $registration -or $registration.version -ne 2 -or [string]::IsNullOrWhiteSpace($registration.basePath)) { throw "The selected distribution '$($script:distro)' is not conclusively registered as WSL version 2." }

$script:machineFingerprint = Get-EnvoyMachineFingerprint
$script:windowsOwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$projectRoot = Split-Path $PSScriptRoot -Parent
$stateDir = Join-Path $projectRoot 'state'
$statePath = Join-Path $stateDir 'compute-current.json'
Assert-ExactComputeStateAcl -Path $stateDir -OwnerSid $script:windowsOwnerSid -IsDirectory $true
Assert-ExactComputeStateAcl -Path $statePath -OwnerSid $script:windowsOwnerSid -IsDirectory $false
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
if ($state.schemaVersion -ne 2 -or $state.machineFingerprint -cne $script:machineFingerprint -or
    $state.windowsOwnerSid -cne $script:windowsOwnerSid -or $state.distribution -cne $script:distro -or
    $state.createdByEnvoyNode -isnot [bool] -or -not [bool]$state.createdByEnvoyNode -or $state.status -cne 'ready-on-demand' -or
    $state.managedMarkerStatus -cne 'ready' -or $state.wslVersion -ne 2 -or
    $state.registrationId -cne $registration.registrationId -or $state.registrationBasePath -cne $registration.basePath) {
    throw 'Protected compute state does not exactly match this machine, owner, ready lifecycle, and live WSL2 registration.'
}

if ($OfflineOnly) {
    $offlineReport = [pscustomobject][ordered]@{
        reportVersion = 2
        generatedUtc = [DateTime]::UtcNow.ToString('o')
        proofMode = 'offline-binding-only'
        passed = $true
        windowsOwner = $env:USERNAME
        machineFingerprint = $script:machineFingerprint
        distribution = $script:distro
        registrationId = $registration.registrationId
        registrationBasePath = $registration.basePath
        wslVersion = $registration.version
        protectedStateValidated = $true
        exactMarkerValidated = $false
        liveProofSkipped = $true
        note = 'The distribution was not launched. Linux marker, user, Docker, networking, and smoke proofs remain deferred.'
    }
    if (-not $NoReport) {
        if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $projectRoot 'reports\compute-binding-latest.json' }
        $offlineDirectory = Split-Path $OutputPath -Parent
        if ($offlineDirectory -and -not (Test-Path -LiteralPath $offlineDirectory)) { New-Item -ItemType Directory -Path $offlineDirectory -Force | Out-Null }
        $offlineReport | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    }
    if ($PassThru) { return $offlineReport }
    if ($Json) { $offlineReport | ConvertTo-Json -Depth 8 }
    else { Write-Output "PASS: protected state and the live WSL2 registration are exactly bound for stopped distribution $($script:distro); live proof was skipped." }
    return
}

if ($RequireAlreadyRunning) {
    $runningText = ((& $script:WslExe --list --running --quiet 2>$null | Out-String) -replace "`0", '')
    if ($LASTEXITCODE -ne 0) { throw 'Could not conclusively recheck WSL running state before live compute verification.' }
    $runningNow = @($runningText -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($runningNow -notcontains $script:distro) { throw 'The compute distribution stopped before live verification. Refusing to wake it from General Verify.' }
}

$markerProbe = @'
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
$markerJson = Invoke-WslScriptChecked -Distribution $script:distro -ScriptText $markerProbe
Assert-ExactManagedMarker -JsonText $markerJson

$userTemplate = @'
set -euo pipefail
export ENVOY_COMPUTE_USER='__LINUX_USER__'
python3 - <<'PY'
import configparser
import grp
import json
import os
import pwd
import shutil
import spwd
import stat
import subprocess
import sys

user = os.environ["ENVOY_COMPUTE_USER"]
entry = pwd.getpwnam(user)
groups = sorted({g.gr_name for g in grp.getgrall() if user in g.gr_mem} | {grp.getgrgid(entry.pw_gid).gr_name})
shadow = spwd.getspnam(user).sp_pwdp
home_stat = os.lstat(entry.pw_dir)
config = configparser.ConfigParser()
config_stat = os.lstat("/etc/wsl.conf")
with open("/etc/wsl.conf", "r", encoding="utf-8") as handle:
    config_text = handle.read()
config.read_string(config_text)
expected_config = f"[boot]\nsystemd=true\n[user]\ndefault={user}\n[automount]\nenabled=false\n[interop]\nenabled=false\nappendWindowsPath=false\n"
default_user = config.get("user", "default", fallback="")
systemd_enabled = config.getboolean("boot", "systemd", fallback=False)
automount_enabled = config.getboolean("automount", "enabled", fallback=True)
interop_enabled = config.getboolean("interop", "enabled", fallback=True)
windows_path_appended = config.getboolean("interop", "appendWindowsPath", fallback=True)
privileged = sorted(set(groups) & {"root", "sudo", "wheel", "adm", "docker"})
sudo_path = shutil.which("sudo")
sudo_check = subprocess.run([sudo_path, "-n", "-l", "-U", user], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) if sudo_path else None
sudo_rule_present = sudo_check is not None and sudo_check.returncode == 0
sudo_check_error = sudo_check is not None and sudo_check.returncode not in {0, 1}
windows_drive_mounted = os.path.ismount("/mnt/c")
interop_handler_present = os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop")
wsl_config_safe = (
    stat.S_ISREG(config_stat.st_mode)
    and not os.path.islink("/etc/wsl.conf")
    and config_stat.st_uid == 0
    and config_stat.st_gid == 0
    and stat.S_IMODE(config_stat.st_mode) == 0o644
    and config_text == expected_config
)
result = {
    "user": user,
    "uid": entry.pw_uid,
    "gid": entry.pw_gid,
    "home": entry.pw_dir,
    "shell": entry.pw_shell,
    "passwordLocked": shadow.startswith(("!", "*")),
    "privilegedGroups": privileged,
    "directSudoersGrant": sudo_rule_present,
    "sudoInspectionComplete": not sudo_check_error,
    "defaultWslUser": default_user,
    "homeMode": oct(stat.S_IMODE(home_stat.st_mode)),
    "systemdEnabled": systemd_enabled,
    "automountEnabled": automount_enabled,
    "interopEnabled": interop_enabled,
    "windowsPathAppended": windows_path_appended,
    "windowsDriveMounted": windows_drive_mounted,
    "interopHandlerPresent": interop_handler_present,
    "wslConfigSafe": wsl_config_safe,
}
safe = (
    entry.pw_uid >= 1000
    and entry.pw_uid != 65534
    and entry.pw_dir == f"/home/{user}"
    and entry.pw_shell == "/bin/bash"
    and result["passwordLocked"]
    and not privileged
    and not sudo_rule_present
    and not sudo_check_error
    and default_user == user
    and systemd_enabled
    and not automount_enabled
    and not interop_enabled
    and not windows_path_appended
    and not windows_drive_mounted
    and not interop_handler_present
    and result["wslConfigSafe"]
    and stat.S_ISDIR(home_stat.st_mode)
    and not os.path.islink(entry.pw_dir)
    and home_stat.st_uid == entry.pw_uid
    and home_stat.st_gid == entry.pw_gid
    and stat.S_IMODE(home_stat.st_mode) == 0o750
)
print(json.dumps(result, separators=(",", ":")))
if not safe:
    sys.exit(45)
PY
'@
$userScript = $userTemplate.Replace('__LINUX_USER__', $linuxUser)
$userProofJson = Invoke-WslScriptChecked -Distribution $script:distro -ScriptText $userScript
$userProof = $userProofJson | ConvertFrom-Json
$effectiveDefaultUser = Get-EffectiveWslDefaultUser -Distribution $script:distro
if ($effectiveDefaultUser -cne $linuxUser) { throw "The effective WSL default user is '$effectiveDefaultUser', expected dedicated account '$linuxUser'." }

$serviceState = Invoke-WslChecked -Distribution $script:distro -ArgumentList @('systemctl', 'is-active', 'docker.service')
$serviceEnabled = Invoke-WslChecked -Distribution $script:distro -ArgumentList @('systemctl', 'is-enabled', 'docker.service')
$serverVersion = Invoke-WslChecked -Distribution $script:distro -ArgumentList @('env', '-u', 'DOCKER_HOST', '-u', 'DOCKER_CONTEXT', 'docker', '--host', 'unix:///run/docker.sock', 'info', '--format', '{{.ServerVersion}}')
$composeVersion = Invoke-WslChecked -Distribution $script:distro -ArgumentList @('env', '-u', 'DOCKER_HOST', '-u', 'DOCKER_CONTEXT', 'docker', '--host', 'unix:///run/docker.sock', 'compose', 'version', '--short')

$postureScript = @'
set -euo pipefail
python3 - <<'PY'
import json
import os
import pathlib
import stat
import subprocess

clean_docker_env = os.environ.copy()
clean_docker_env.pop("DOCKER_HOST", None)
clean_docker_env.pop("DOCKER_CONTEXT", None)

def output(args, env=None):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, env=env).strip()

def docker_output(args):
    return output(["docker", "--host", "unix:///run/docker.sock", *args], env=clean_docker_env)

ids = [item for item in docker_output(["ps", "-aq"]).splitlines() if item]
containers = json.loads(docker_output(["inspect", *ids])) if ids else []
host_network = []
unsafe_published = []
published = []
seen_bindings = set()
for container in containers:
    container_id = container.get("Id", "")
    host_config = container.get("HostConfig", {}) or {}
    mode = str(host_config.get("NetworkMode", ""))
    if mode == "host":
        host_network.append(container_id)
    port_sources = [
        ("configured", host_config.get("PortBindings") or {}),
        ("live", container.get("NetworkSettings", {}).get("Ports") or {}),
    ]
    for source, ports in port_sources:
        for container_port, bindings in ports.items():
            for binding in bindings or []:
                host_ip = str(binding.get("HostIp", ""))
                host_port = str(binding.get("HostPort", ""))
                key = (container_id, container_port, host_ip, host_port)
                if key in seen_bindings:
                    continue
                seen_bindings.add(key)
                item = {"containerId": container_id, "containerPort": container_port, "hostIp": host_ip, "hostPort": host_port, "source": source}
                published.append(item)
                if host_ip not in {"127.0.0.1", "::1"}:
                    unsafe_published.append(item)
    if bool(host_config.get("PublishAllPorts")):
        item = {"containerId": container_id, "containerPort": "*", "hostIp": "<publish-all-default>", "hostPort": "*", "source": "configured"}
        published.append(item)
        unsafe_published.append(item)

daemon_config_hosts = []
daemon_path = pathlib.Path("/etc/docker/daemon.json")
if daemon_path.exists():
    if daemon_path.is_symlink() or not daemon_path.is_file():
        raise SystemExit("Unsafe /etc/docker/daemon.json file type")
    data = json.loads(daemon_path.read_text(encoding="utf-8"))
    hosts = data.get("hosts", [])
    if isinstance(hosts, str):
        hosts = [hosts]
    daemon_config_hosts.extend(str(host) for host in hosts if str(host).lower().startswith("tcp://"))

exec_start = output(["systemctl", "show", "docker.service", "--property", "ExecStart", "--value"])
daemon_exec_tcp_hosts = [token for token in exec_start.replace(";", " ").split() if "tcp://" in token.lower()]
socket_unit = subprocess.run(["systemctl", "cat", "docker.socket"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
socket_listen_values = []
if socket_unit.returncode == 0:
    socket_listen_values = [line.split("=", 1)[1].strip() for line in socket_unit.stdout.splitlines() if line.strip().startswith("ListenStream=")]
unsafe_socket_listeners = [value for value in socket_listen_values if value not in {"/run/docker.sock", "/var/run/docker.sock"}]
if "fd://" in exec_start and not socket_listen_values:
    unsafe_socket_listeners.append("fd:// without a readable docker.socket ListenStream")
main_pid = output(["systemctl", "show", "docker.service", "--property", "MainPID", "--value"])
if not main_pid.isdigit() or int(main_pid) <= 0:
    raise SystemExit("Docker service has no live MainPID")
socket_lines = output(["ss", "-H", "-lntp"]).splitlines()
dockerd_tcp_listeners = [line for line in socket_lines if f"pid={main_pid}," in line or '(("dockerd"' in line]

default_context = json.loads(output(["docker", "context", "inspect", "default"], env=clean_docker_env))[0]
default_endpoint = str(default_context.get("Endpoints", {}).get("docker", {}).get("Host", ""))
socket_path = pathlib.Path("/run/docker.sock")
socket_stat = os.lstat(socket_path)
unix_socket_safe = (
    stat.S_ISSOCK(socket_stat.st_mode)
    and not socket_path.is_symlink()
    and socket_stat.st_uid == 0
    and (stat.S_IMODE(socket_stat.st_mode) & 0o007) == 0
    and default_endpoint in {"unix:///var/run/docker.sock", "unix:///run/docker.sock"}
)

result = {
    "hostNetworkContainers": host_network,
    "publishedBindings": published,
    "unsafePublishedPorts": unsafe_published,
    "configuredTcpHosts": sorted(set(daemon_config_hosts + daemon_exec_tcp_hosts + unsafe_socket_listeners)),
    "dockerdTcpListeners": dockerd_tcp_listeners,
    "defaultDockerEndpoint": default_endpoint,
    "unixSocketSafe": unix_socket_safe,
    "unixSocketMode": oct(stat.S_IMODE(socket_stat.st_mode)),
    "unixSocketUid": socket_stat.st_uid,
    "unixSocketGid": socket_stat.st_gid,
}
print(json.dumps(result, separators=(",", ":")))
PY
'@
$postureJson = Invoke-WslScriptChecked -Distribution $script:distro -ScriptText $postureScript
$posture = $postureJson | ConvertFrom-Json

$image = 'docker.io/library/hello-world@sha256:7f4da0fc94bcece205a8c0b6f4d11c8196924654ffe5c4d1aa439b7f632048b2'
$smokeOutput = $null
$isolatedSmokePassed = $null
if (-not $SkipSmoke) {
    $null = Invoke-WslChecked -Distribution $script:distro -ArgumentList @('env', '-u', 'DOCKER_HOST', '-u', 'DOCKER_CONTEXT', 'docker', '--host', 'unix:///run/docker.sock', 'image', 'inspect', $image)
    $containerName = 'envoy-compute-verify-' + ([Guid]::NewGuid().ToString('N').Substring(0, 12))
    $smokeOutput = Invoke-WslChecked -Distribution $script:distro -ArgumentList @(
        'env', '-u', 'DOCKER_HOST', '-u', 'DOCKER_CONTEXT', 'docker', '--host', 'unix:///run/docker.sock', 'run', '--rm', '--name', $containerName,
        '--label', 'io.envoynode.managed=true', '--network', 'none', '--read-only',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '32',
        '--memory', '64m', '--cpus', '0.5', '--user', '65534:65534', $image
    )
    $isolatedSmokePassed = [bool]($smokeOutput -match 'Hello from Docker')
}

$hostNetworkContainers = @($posture.hostNetworkContainers)
$unsafePublished = @($posture.unsafePublishedPorts)
$configuredTcpHosts = @($posture.configuredTcpHosts)
$dockerdTcpListeners = @($posture.dockerdTcpListeners)
$unixSocketSafe = [bool]$posture.unixSocketSafe
$report = [pscustomobject][ordered]@{
    reportVersion = 2
    generatedUtc = [DateTime]::UtcNow.ToString('o')
    passed = [bool](
        $serviceState -eq 'active' -and
        $serviceEnabled -eq 'enabled' -and
        -not [string]::IsNullOrWhiteSpace($serverVersion) -and
        -not [string]::IsNullOrWhiteSpace($composeVersion) -and
        $hostNetworkContainers.Count -eq 0 -and
        $unsafePublished.Count -eq 0 -and
        $configuredTcpHosts.Count -eq 0 -and
        $dockerdTcpListeners.Count -eq 0 -and
        $unixSocketSafe -and
        ($SkipSmoke -or $isolatedSmokePassed)
    )
    windowsOwner = $env:USERNAME
    machineFingerprint = $script:machineFingerprint
    distribution = $script:distro
    registrationId = $registration.registrationId
    wslVersion = $registration.version
    protectedStateValidated = $true
    exactMarkerValidated = $true
    linuxUser = $userProof
    effectiveDefaultWslUser = $effectiveDefaultUser
    dockerService = $serviceState
    dockerServiceEnabled = $serviceEnabled
    dockerServerVersion = $serverVersion
    dockerComposeVersion = $composeVersion
    configuredTcpHosts = $configuredTcpHosts
    dockerdTcpListeners = $dockerdTcpListeners
    defaultDockerEndpoint = $posture.defaultDockerEndpoint
    unixSocketSafe = $unixSocketSafe
    unixSocketMode = $posture.unixSocketMode
    unixSocketUid = $posture.unixSocketUid
    unixSocketGid = $posture.unixSocketGid
    hostNetworkContainers = $hostNetworkContainers
    publishedBindings = @($posture.publishedBindings)
    unsafePublishedPorts = $unsafePublished
    smokeImage = $image
    smokeExecuted = [bool](-not $SkipSmoke)
    isolatedSmokePassed = $isolatedSmokePassed
}

if (-not $NoReport) {
    if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $projectRoot 'reports\compute-verify-latest.json' }
    $directory = Split-Path $OutputPath -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
}

if ($PassThru) { return $report }
if ($Json) { $report | ConvertTo-Json -Depth 10 }
elseif ($report.passed -and $SkipSmoke) { Write-Output "PASS: running dedicated WSL2 engine $serverVersion has the required read-only posture; transient smoke was intentionally skipped." }
elseif ($report.passed) { Write-Output "PASS: dedicated WSL2 engine $serverVersion uses no TCP Docker API or host networking and ran the pinned isolated smoke image." }
else { Write-Output 'FAIL: dedicated WSL compute engine verification failed.' }
if (-not $report.passed) { exit 1 }
exit 0
