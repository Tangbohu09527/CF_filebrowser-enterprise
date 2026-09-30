# Offline 0.3.0 -> 0.4.0 plugin upgrade. Default Check never writes or starts Hermes/services.
[CmdletBinding()]
param(
    [ValidateSet('Check','Prepare','Apply','Resume','SelfTest')][string]$Mode='Check',
    [string]$BundleDirectory='', [string]$ExpectedInventorySHA256='',
    [string]$HermesHome='', [string]$Profile='', [string]$PythonPath='',
    [string]$UpgradeDirectory='',
    [string]$PreviousBundleInventoryPath='', [string]$ExpectedPreviousInventorySHA256='',
    [switch]$HermesStopped
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw 'Native Windows PowerShell 5.1 required.'
}
if ($Mode -eq 'SelfTest') { & (Join-Path $PSScriptRoot '../tests/Test-InboundUpgrade.ps1') -PythonPath $PythonPath; return }
if (-not $BundleDirectory -or -not $HermesHome -or
    $ExpectedInventorySHA256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Explicit bundle, inventory digest, HermesHome and PythonPath are required.' }
if ($Mode -in @('Apply','Resume') -and -not $HermesStopped) { throw 'CF_UPGRADE_OPERATOR_MUST_CONFIRM_HERMES_STOPPED' }
if ($Mode -ne 'Check' -and -not $UpgradeDirectory) { throw 'A separate private UpgradeDirectory is required for explicit write modes.' }
if ($PreviousBundleInventoryPath -and $ExpectedPreviousInventorySHA256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'An explicit previous inventory requires its independent SHA-256.'
}
if (-not $PythonPath) { $PythonPath=Join-Path $HermesHome 'hermes-agent/venv/Scripts/python.exe' }
$stageDriver=Join-Path $PSScriptRoot 'Manage-InboundClient.ps1'
. (Join-Path $PSScriptRoot 'ConfigFile.ps1')
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$directories=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$streams=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$oldPluginNames=@('__init__.py','plugin.yaml','inbound.py','inbound_control.py','inbound_directory.py','inbound_host.py')
$pluginNames=@($oldPluginNames)+@('inbound_content.py')
$utf8=[Text.UTF8Encoding]::new($false)
$runtimePython='';$runtimeHash=''
$upgrade=$null

function LocalPath([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.Substring(2).Contains(':') -or
        $Path -match '[\\/](\.|\.\.)([\\/]|$)' -or $Path -match '[ .]([\\/]|$)') { throw 'CF_UPGRADE_LOCAL_PATH_REQUIRED' }
    $value=[IO.Path]::GetFullPath($Path).TrimEnd('\','/')
    if ($value.Length -lt 4) { throw 'CF_UPGRADE_DRIVE_ROOT_REFUSED' }
    return $value
}
function Hold([string]$Path) {
    if ($directories.ContainsKey($Path)) { [CfInboundStageNative]::CheckDirectory($directories[$Path]); return }
    $parent=[IO.Directory]::GetParent($Path)
    if ($parent) { Hold $parent.FullName }
    $directories.Add($Path,[CfInboundStageNative]::LockDirectory($Path))
}
function Private([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'CF_UPGRADE_REPARSE_REFUSED' }
    $acl=Get-Acl -LiteralPath $Path
    $allowed=@($sid,'S-1-5-18','S-1-5-32-544')
    if ($allowed -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -or -not $acl.AreAccessRulesCanonical) {
        throw 'CF_UPGRADE_PRIVATE_OWNER_REQUIRED'
    }
    if ($item.PSIsContainer -and -not $acl.AreAccessRulesProtected) { throw 'CF_UPGRADE_PRIVATE_DIRECTORY_REQUIRED' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($allowed -notcontains $rule.IdentityReference.Value -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw 'CF_UPGRADE_PRIVATE_ACL_REQUIRED_NO_REPAIR'
        }
    }
}
function Security([bool]$Directory) {
    $acl=if ($Directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($sid));$acl.SetAccessRuleProtection($true,$false)
    $inherit=if ($Directory) { [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($who in @($sid,'S-1-5-18') | Select-Object -Unique) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($who),
            [Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    return $acl
}
function NewDirectory([string]$Path) {
    Hold ([IO.Path]::GetDirectoryName($Path))
    if (Test-Path -LiteralPath $Path) { Hold $Path;Private $Path;return }
    [CfInboundStageNative]::CreateDirectory($Path,(Security $true).GetSecurityDescriptorBinaryForm())
    Hold $Path;Private $Path
}
function HashBytes([byte[]]$Bytes) {
    $hash=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $hash.Dispose() }
}
function ReadLocked([string]$Path,[string]$Expected='',[bool]$RequirePrivate=$false) {
    Hold ([IO.Path]::GetDirectoryName($Path))
    if ($RequirePrivate) { Private $Path }
    if (-not $streams.ContainsKey($Path)) {
        $handle=[CfInboundStageNative]::OpenFileRead($Path)
        try { $streams.Add($Path,[IO.FileStream]::new($handle,[IO.FileAccess]::Read)) } catch { $handle.Dispose();throw }
    }
    $stream=$streams[$Path];[CfInboundStageNative]::CheckFile($stream.SafeFileHandle)
    if ($stream.Length -gt 64L*1024*1024) { throw 'CF_UPGRADE_INPUT_TOO_LARGE' }
    $stream.Position=0;$memory=[IO.MemoryStream]::new()
    try { $stream.CopyTo($memory);$bytes=$memory.ToArray() } finally { $memory.Dispose() }
    $stream.Position=0
    if ($Expected -and (HashBytes $bytes) -cne $Expected.ToLowerInvariant()) { throw 'CF_UPGRADE_FILE_DIGEST_CONFLICT' }
    return ,$bytes
}
function ReleaseFile([string]$Path) {
    if ($streams.ContainsKey($Path)) { $streams[$Path].Dispose();$streams.Remove($Path) | Out-Null }
}
function NewFile([string]$Path,[byte[]]$Bytes) {
    if (Test-Path -LiteralPath $Path) {
        $existing=ReadLocked $Path (HashBytes $Bytes) $true
        return
    }
    Hold ([IO.Path]::GetDirectoryName($Path))
    $stream=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::FullControl,
        [IO.FileShare]::None,65536,[IO.FileOptions]::WriteThrough,(Security $false))
    try { $stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true);[CfInboundStageNative]::CheckFile($stream.SafeFileHandle) }
    finally { $stream.Dispose() }
    $verified=ReadLocked $Path (HashBytes $Bytes) $true
}
function Get-CfUpgradeSafePythonFailure([string]$Text,[string]$ExpectedStage) {
    $safeStages=@('config_semantic_plan','runtime_dependencies','runtime_extract_wheels','runtime_inventory')
    $safeErrors=@(
        'absolute_path_required','reparse_refused','input_size_or_type','yaml_mapping_required','plugin_version_conflict',
        'existing_plugin_not_enabled','existing_inbound_not_enabled','existing_host_settings_missing','existing_host_settings_incomplete',
        'existing_profile_revision_invalid','existing_worker_digest_invalid','consumer_allowlist_missing','api_toolsets_missing',
        'runtime_pin_invalid','yaml_alias_changes_unrelated_settings','candidate_size_exceeded','candidate_roundtrip_failed',
        'dependency_inventory_invalid','dependency_inventory_incomplete','runtime_reparse_refused','runtime_size_exceeded',
        'runtime_node_refused','runtime_empty','checkpoint_conflict','wheels_directory_required','wheel_archive_shape',
        'wheel_archive_member','wheel_archive_size','runtime_modified_or_unknown','candidate_absolute_required','prepared_candidate_conflict',
        'configuration_plan_failed','platform_toolsets_invalid','api_toolsets_invalid','known_plugin_toolsets_invalid',
        'agent_configuration_invalid','disabled_toolsets_invalid','content_toolset_disabled'
    )
    if ($Text.Length -gt 512 -or $safeStages -cnotcontains $ExpectedStage) { return $null }
    # Deliberately accept only the planner's fixed three-key serialization.
    # A strict shape rejects duplicate keys, extra fields, free text and JSON
    # string escapes before any diagnostic can reach an operator's terminal.
    $match=[regex]::Match($Text,'\A\s*\{\s*"ok"\s*:\s*false\s*,\s*"stage"\s*:\s*"([a-z_]+)"\s*,\s*"error"\s*:\s*"([a-z_]+)"\s*\}\s*\z')
    if (-not $match.Success -or $match.Groups[1].Value -cne $ExpectedStage -or $safeErrors -cnotcontains $match.Groups[2].Value) { return $null }
    return ('CF_UPGRADE_PYTHON_STEP_FAILED:'+$ExpectedStage+':'+$match.Groups[2].Value)
}
function Get-CfUpgradePlannerVersion($Info) {
    if ($null -eq $Info -or @($Info.PSObject.Properties).Count -ne 4 -or
        $null -eq $Info.PSObject.Properties['version'] -or $null -eq $Info.PSObject.Properties['bits'] -or
        $null -eq $Info.PSObject.Properties['platform'] -or $null -eq $Info.PSObject.Properties['implementation']) {
        throw 'CF_UPGRADE_UNSUPPORTED_PYTHON_ABI'
    }
    $version=@($Info.version)
    if ($version.Count -ne 3 -or ($Info.bits -isnot [int] -and $Info.bits -isnot [long]) -or $Info.bits -ne 64 -or $Info.platform -cne 'win-amd64' -or $Info.implementation -cne 'cpython') {
        throw 'CF_UPGRADE_UNSUPPORTED_PYTHON_ABI'
    }
    foreach ($part in $version) {
        if (($part -isnot [int] -and $part -isnot [long]) -or $part -lt 0) { throw 'CF_UPGRADE_UNSUPPORTED_PYTHON_ABI' }
    }
    if ($version[0] -ne 3 -or $version[1] -notin @(11,14)) { throw 'CF_UPGRADE_UNSUPPORTED_PYTHON_ABI' }
    return ($version -join '.')
}
function Assert-CfUpgradeTargetPip($Version) {
    # pip documents --python for managing a pip-less venv from version 22.3.
    # Never upgrade the selected planner's packages to acquire this capability.
    if ($Version -isnot [string] -or $Version.Length -gt 24 -or $Version -cnotmatch '^[0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?$') { throw 'CF_UPGRADE_PLANNER_PIP_UNSUPPORTED' }
    $parts=$Version.Split('.')
    if ([long]$parts[0] -lt 22 -or ([long]$parts[0] -eq 22 -and [long]$parts[1] -lt 3)) { throw 'CF_UPGRADE_PLANNER_PIP_UNSUPPORTED' }
}
function RunPython([string]$Executable,[string[]]$Arguments,[bool]$Json=$true,[string]$FailureStage='') {
    # Only this explicit interpreter; no inherited credentials or package-index
    # settings. stdout/stderr stay private and only bounded metadata is emitted.
    $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$Executable
    foreach ($argument in $Arguments) { if ($argument.Contains('"') -or $argument.EndsWith('\')) { throw 'CF_UPGRADE_ARGUMENT_REFUSED' } }
    $start.Arguments=(@($Arguments | ForEach-Object { '"'+$_+'"' }) -join ' ')
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $start.EnvironmentVariables.Clear()
    $start.EnvironmentVariables['SystemRoot']=$env:SystemRoot
    $start.EnvironmentVariables['WINDIR']=$env:SystemRoot
    # pip --python re-launches the target without the parent's -I/-B flags.
    # These fixed values also protect that child from user-site and pyc writes.
    $start.EnvironmentVariables['PYTHONDONTWRITEBYTECODE']='1'
    $start.EnvironmentVariables['PYTHONNOUSERSITE']='1'
    $start.EnvironmentVariables['PATH']=[IO.Path]::GetDirectoryName($Executable)+';'+(Join-Path $env:SystemRoot 'System32')
    # Before preparation, use the operator-selected private profile only as a
    # read-only HOME. Python is isolated and no Hermes module is imported.
    $privateHome=if ($script:upgrade -and (Test-Path -LiteralPath $script:upgrade)) { $script:upgrade } else { $script:profileRoot }
    $start.EnvironmentVariables['HOME']=$privateHome;$start.EnvironmentVariables['USERPROFILE']=$privateHome
    $start.EnvironmentVariables['HERMES_HOME']=$privateHome
    $start.EnvironmentVariables['TEMP']=$privateHome;$start.EnvironmentVariables['TMP']=$privateHome
    $start.WorkingDirectory=$privateHome
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start
    try {
        if (-not $process.Start()) { throw 'CF_UPGRADE_PYTHON_START_FAILED' }
        $output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(120000)) { $process.Kill();$process.WaitForExit();throw 'CF_UPGRADE_PYTHON_TIMEOUT' }
        $text=$output.GetAwaiter().GetResult();$privateError=$errors.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            $safeFailure=$null
            if ($Json -and $FailureStage -and $Arguments.Count -ge 5 -and $Arguments[0] -ceq '-I' -and
                $Arguments[1] -ceq '-X' -and $Arguments[2] -ceq 'utf8' -and $Arguments[3] -ceq '-B' -and
                [IO.Path]::IsPathRooted($Arguments[4])) {
                $plannerScript=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'inbound_upgrade_config.py'))
                if ([IO.Path]::GetFullPath($Arguments[4]).Equals($plannerScript,[StringComparison]::OrdinalIgnoreCase)) {
                    $safeFailure=Get-CfUpgradeSafePythonFailure $text $FailureStage
                }
            }
            if ($safeFailure) { throw $safeFailure }
            throw 'CF_UPGRADE_PYTHON_STEP_FAILED_NO_PRIVATE_OUTPUT'
        }
        if ($Json) {
            try { return ($text | ConvertFrom-Json) }
            catch { throw 'CF_UPGRADE_PYTHON_RESPONSE_INVALID_NO_PRIVATE_OUTPUT' }
        }
    } finally { $process.Dispose() }
}
function RunPlanner([string]$Candidate='') {
    $arguments=@('-I','-X','utf8','-B',(Join-Path $PSScriptRoot 'inbound_upgrade_config.py'),
        '--config',$config,'--installed-manifest',(Join-Path $plugin 'plugin.yaml'),
        '--release-manifest',(Join-Path $bundle 'plugin/plugin.yaml'),
        '--requirements',(Join-Path $bundle 'requirements-inbound-content.txt'))
    if ($Candidate) { $arguments+=@('--candidate',$Candidate) }
    if ($runtimePython) { $arguments+=@('--runtime-python',$runtimePython,'--runtime-sha256',$runtimeHash) }
    $value=RunPython $python $arguments $true 'config_semantic_plan'
    if (-not $value.ok) { throw 'CF_UPGRADE_CONFIGURATION_PLAN_FAILED' }
    return $value
}
function RuntimeArguments([string[]]$Arguments) {
    return @('-I','-X','utf8','-B',(Join-Path $PSScriptRoot 'inbound_upgrade_config.py'),
        '--requirements',(Join-Path $bundle 'requirements-inbound-content.txt'))+$Arguments
}
function AssertStopped {
    # Exact executable-path query only. Never fetch command lines/environment,
    # inspect session contents, or stop an operator's service/process.
    $executables=RunPython $python @('-I','-X','utf8','-B','-c',"import json,sys; print(json.dumps([sys.executable,sys._base_executable]))")
    foreach ($executable in @($executables | Select-Object -Unique)) {
        $exact=LocalPath $executable
        $escaped=$exact.Replace('\','\\').Replace("'","\'")
        $running=@(Get-CimInstance -ClassName Win32_Process -Filter ("ExecutablePath='"+$escaped+"'") -Property ExecutablePath,ProcessId)
        if ($running.Count -ne 0) { throw 'CF_UPGRADE_SELECTED_HERMES_PYTHON_STILL_RUNNING' }
    }
    # The selected planner can differ from the serving runtime. Constrain the
    # provider query to this exact HermesHome subtree; never fetch command lines
    # or inspect processes in another application's directory.
    $hermesPrefix=(LocalPath $HermesHome)+'\'
    $likePrefix=$hermesPrefix.Replace('[','[[]').Replace('%','[%]').Replace('_','[_]').Replace('\','\\').Replace("'","\'")
    $running=@(Get-CimInstance -ClassName Win32_Process -Filter ("Name LIKE 'python%.exe' AND ExecutablePath LIKE '"+$likePrefix+"%'") -Property ExecutablePath,ProcessId)
    foreach ($process in $running) {
        if ($process.ExecutablePath -and $process.ExecutablePath.StartsWith($hermesPrefix,[StringComparison]::OrdinalIgnoreCase) -and
            [IO.Path]::GetFileName($process.ExecutablePath) -match '^python(?:[0-9]+(?:\.[0-9]+)*)?w?\.exe$') {
            throw 'CF_UPGRADE_HERMES_HOME_PYTHON_STILL_RUNNING'
        }
    }
}
function PrepareRuntime {
    $runtime=Join-Path $upgrade 'parser-runtime';$receipt=Join-Path $upgrade 'runtime.inventory.json'
    if (Test-Path -LiteralPath $runtime) {
        Hold $runtime;Private $runtime
        if (-not (Test-Path -LiteralPath $receipt)) { throw 'CF_UPGRADE_PARTIAL_RUNTIME_PRESERVED_USE_NEW_PLAN_DIRECTORY' }
        if ($checkpoint) { $verified=ReadLocked $receipt $checkpoint.runtime_inventory_sha256 $true }
        $check=RunPython $python (RuntimeArguments @('--runtime-receipt',$receipt,'--runtime-root',$runtime,'--verify-runtime')) $true 'runtime_inventory'
    } else {
        $pipVersion=RunPython $python @('-I','-X','utf8','-B','-c',"import json,importlib.util,importlib.metadata;print(json.dumps(importlib.metadata.version('pip') if importlib.util.find_spec('pip') is not None else None))")
        Assert-CfUpgradeTargetPip $pipVersion
        $wheels=Join-Path $upgrade 'wheels';NewDirectory $wheels
        $extracted=RunPython $python (RuntimeArguments @('--extract-wheels','--wheel-archive',(Join-Path $bundle 'content-wheels.zip'),'--wheels',$wheels)) $true 'runtime_extract_wheels'
        NewDirectory $runtime
        RunPython $python @('-I','-X','utf8','-B','-m','venv','--without-pip',$runtime) $false
        $createdPython=Join-Path $runtime 'Scripts/python.exe'
        RunPython $python @('-I','-X','utf8','-B','-m','pip','--isolated','--python',$createdPython,'install','--no-index','--no-cache-dir',
            '--no-compile','--only-binary=:all:','--no-deps','--require-hashes','--find-links',$wheels,
            '-r',(Join-Path $bundle 'requirements-inbound-content.txt')) $false
        $check=RunPython $python (RuntimeArguments @('--runtime-receipt',$receipt,'--runtime-root',$runtime)) $true 'runtime_inventory'
    }
    $script:runtimePython=Join-Path $runtime 'Scripts/python.exe'
    $script:runtimeHash=HashBytes (ReadLocked $runtimePython '' $true)
    $status=RunPython $runtimePython (RuntimeArguments @('--dependencies-only')) $true 'runtime_dependencies'
    if (-not $status.dependency_ready) { throw 'CF_UPGRADE_OFFLINE_RUNTIME_DEPENDENCY_MISMATCH' }
    return $status
}
function ReplaceKnown([string]$Path,[byte[]]$Bytes,[string]$Before,[string]$After) {
    $actual=HashBytes (ReadLocked $Path '' $true)
    if ($actual -ceq $After) { return }
    if ($actual -cne $Before) { throw 'CF_UPGRADE_CONCURRENT_CONTENT_CONFLICT' }
    $beforeInfo=Get-Item -LiteralPath $Path
    $beforeLength=$beforeInfo.Length;$beforeTime=$beforeInfo.LastWriteTimeUtc
    $sddl=Get-CfConfigSddl $Path
    ReleaseFile $Path
    $result=Set-CfConfigBytesExact -Destination $Path -Bytes $Bytes -BeforeSha256 $Before -AfterSha256 $After -OriginalSddl $sddl
    if ($Path.EndsWith('.py',[StringComparison]::OrdinalIgnoreCase) -and $beforeLength -eq $Bytes.Length) {
        $afterTime=(Get-Item -LiteralPath $Path).LastWriteTimeUtc
        $epoch=[DateTime]::SpecifyKind([DateTime]'1970-01-01',[DateTimeKind]::Utc)
        if ([Math]::Floor(($beforeTime-$epoch).TotalSeconds) -eq [Math]::Floor(($afterTime-$epoch).TotalSeconds)) {
            # Preserve opaque __pycache__ bytes. Timestamp-based Python caches
            # must still invalidate when same-size source changes in one second.
            [IO.File]::SetLastWriteTimeUtc($Path,$beforeTime.AddSeconds(2))
        }
    }
    $verified=ReadLocked $Path $After $true
}

try {
    $bundle=LocalPath $BundleDirectory;$profileRoot=LocalPath $HermesHome;$python=LocalPath $PythonPath
    $inspection=& $stageDriver -Mode Inspect -SourceDirectory $bundle -ExpectedInventorySHA256 $ExpectedInventorySHA256 | ConvertFrom-Json
    if (-not $inspection.verified -or $inspection.payload_count -ne 10) { throw 'CF_UPGRADE_CONSUMER_BUNDLE_REQUIRED' }
    Hold $profileRoot;Private $profileRoot
    if (-not $Profile -and (Test-Path -LiteralPath (Join-Path $profileRoot 'active_profile'))) {
        $selection=ReadLocked (Join-Path $profileRoot 'active_profile') '' $true
        if ($selection.Length -gt 256) { throw 'CF_UPGRADE_PROFILE_SELECTOR_INVALID' }
        $Profile=$utf8.GetString($selection).Trim()
        if (-not $Profile) { throw 'CF_UPGRADE_PROFILE_SELECTOR_INVALID' }
    }
    if ($Profile -ceq 'default') { $Profile='' }
    if ($Profile) {
        if ($Profile -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$') { throw 'CF_UPGRADE_PROFILE_NAME_INVALID' }
        $profileRoot=Join-Path (Join-Path $profileRoot 'profiles') $Profile
    }
    $plugin=Join-Path $profileRoot 'plugins/cf-filebridge';$config=Join-Path $profileRoot 'config.yaml'
    Hold $profileRoot;Hold $plugin;Private $profileRoot;Private $plugin
    $pythonBytes=ReadLocked $python
    $configBytes=ReadLocked $config '' $true
    if ($configBytes.Length -gt 2097152) { throw 'CF_UPGRADE_CONFIG_TOO_LARGE' }
    foreach ($node in @(Get-ChildItem -LiteralPath $plugin -Force)) {
        if ($node.Name -ceq '__pycache__' -and $node.PSIsContainer) {
            if ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'CF_UPGRADE_REPARSE_CACHE_REFUSED' }
            continue # Preserve opaque bytecode directory; do not inspect it.
        }
        if ($node.PSIsContainer -or $pluginNames -cnotcontains $node.Name) { throw 'CF_UPGRADE_UNKNOWN_PLUGIN_ENTRY_PRESERVED' }
    }
    $newInventory=($utf8.GetString((ReadLocked (Join-Path $bundle 'inventory.json') $ExpectedInventorySHA256))) | ConvertFrom-Json
    foreach ($entry in $newInventory.files.PSObject.Properties) {
        $verified=ReadLocked (Join-Path $bundle $entry.Name) $entry.Value
    }
    $plannerInfo=RunPython $python @('-I','-S','-X','utf8','-B','-c',"import json,sys,struct,sysconfig;print(json.dumps(dict(version=list(sys.version_info[:3]),bits=8*struct.calcsize('P'),platform=sysconfig.get_platform(),implementation=sys.implementation.name)))")
    $plannerVersion=Get-CfUpgradePlannerVersion $plannerInfo
    $plan=RunPlanner
    $worker=LocalPath $plan.worker_path
    $workerBytes=ReadLocked $worker $plan.worker_sha256 $true
    $previous=if ($PreviousBundleInventoryPath) { LocalPath $PreviousBundleInventoryPath } else { Join-Path ([IO.Path]::GetDirectoryName($worker)) 'inventory.json' }
    $previousBytes=ReadLocked $previous $ExpectedPreviousInventorySHA256 $true
    $previousHash=HashBytes $previousBytes
    $old=($utf8.GetString($previousBytes)) | ConvertFrom-Json
    if ($old.schema -cne 'cf-inbound-bundle/v1' -or $old.source_commit -notmatch '^[0-9a-fA-F]{40}$' -or
        $old.files.'filebridge-inbound.exe' -cne $plan.worker_sha256) { throw 'CF_UPGRADE_PREVIOUS_INVENTORY_CONFLICT' }
    $checkpoint=$null;$upgrade=$null
    if ($UpgradeDirectory) {
        $upgrade=LocalPath $UpgradeDirectory
        if ($upgrade.StartsWith($profileRoot+'\',[StringComparison]::OrdinalIgnoreCase) -or $profileRoot.StartsWith($upgrade+'\',[StringComparison]::OrdinalIgnoreCase) -or
            $upgrade.Equals($profileRoot,[StringComparison]::OrdinalIgnoreCase) -or $upgrade.StartsWith($bundle+'\',[StringComparison]::OrdinalIgnoreCase) -or
            $bundle.StartsWith($upgrade+'\',[StringComparison]::OrdinalIgnoreCase) -or $upgrade.Equals($bundle,[StringComparison]::OrdinalIgnoreCase)) {
            throw 'CF_UPGRADE_PLAN_MUST_BE_SEPARATE'
        }
        $upgradeParent=[IO.Path]::GetDirectoryName($upgrade)
        if (Test-Path -LiteralPath $upgradeParent) { Hold $upgradeParent;Private $upgradeParent }
        else { Hold ([IO.Path]::GetDirectoryName($upgradeParent)) }
        if (Test-Path -LiteralPath $upgrade) {
            Hold $upgrade;Private $upgrade
            foreach ($node in @(Get-ChildItem -LiteralPath $upgrade -Force)) {
                if (@('bundle','plugin.before','config.before.yaml','config.after.yaml','upgrade.json','wheels','parser-runtime','runtime.inventory.json') -cnotcontains $node.Name) {
                    throw 'CF_UPGRADE_UNKNOWN_CHECKPOINT_ENTRY_PRESERVED'
                }
            }
            $checkpointPath=Join-Path $upgrade 'upgrade.json'
            if (Test-Path -LiteralPath $checkpointPath) {
                $checkpoint=($utf8.GetString((ReadLocked $checkpointPath '' $true))) | ConvertFrom-Json
                if ($checkpoint.schema -cne 'cf-inbound-upgrade/v1' -or $checkpoint.inventory_sha256 -cne $ExpectedInventorySHA256.ToLowerInvariant() -or
                    $checkpoint.previous_inventory_sha256 -cne $previousHash -or $checkpoint.profile_sha256 -cne (HashBytes $utf8.GetBytes($profileRoot.ToLowerInvariant())) -or
                    $checkpoint.upgrade_directory_sha256 -cne (HashBytes $utf8.GetBytes($upgrade.ToLowerInvariant()))) {
                    throw 'CF_UPGRADE_CHECKPOINT_CONFLICT'
                }
            }
        }
    }
    $originalHashes=@{}
    foreach ($name in $oldPluginNames) {
        $expected=$old.files.PSObject.Properties['plugin/'+$name]
        if ($null -eq $expected -or $expected.Value -notmatch '^[0-9a-fA-F]{64}$') { throw 'CF_UPGRADE_PREVIOUS_PLUGIN_DIGEST_MISSING' }
        $originalHashes[$name]=$expected.Value.ToLowerInvariant()
        $currentHash=HashBytes (ReadLocked (Join-Path $plugin $name) '' $true)
        if ($currentHash -cne $originalHashes[$name] -and
            ($null -eq $checkpoint -or $currentHash -cne $newInventory.files.PSObject.Properties['plugin/'+$name].Value)) {
            throw 'CF_UPGRADE_LOCAL_PLUGIN_MODIFICATION_PRESERVED'
        }
    }
    $contentPath=Join-Path $plugin 'inbound_content.py'
    if (Test-Path -LiteralPath $contentPath) {
        if ($null -eq $checkpoint) { throw 'CF_UPGRADE_UNKNOWN_CONSUMER_FILE_PRESERVED' }
        $verified=ReadLocked $contentPath $newInventory.files.'plugin/inbound_content.py' $true
    }
    if ($checkpoint -and $plan.config_before_sha256 -cne $checkpoint.config_before_sha256 -and
        $plan.config_before_sha256 -cne $checkpoint.config_after_sha256) { throw 'CF_UPGRADE_LOCAL_CONFIG_MODIFICATION_PRESERVED' }
    if ($Mode -eq 'Check') {
        if ($upgrade -and (Test-Path -LiteralPath (Join-Path $upgrade 'runtime.inventory.json'))) {
            if (-not (Test-Path -LiteralPath (Join-Path $upgrade 'parser-runtime'))) { throw 'CF_UPGRADE_RUNTIME_CHECKPOINT_INCOMPLETE' }
            $status=PrepareRuntime
            $plan.dependency_ready=$status.dependency_ready;$plan.dependency_blockers=$status.dependency_blockers
        }
        @{ok=$true;mode=$Mode;planner_python_version=$plannerVersion;writes_performed=$false;configuration_preserved=$true;previous_plugin_verified=$true;
          dependency_ready=$plan.dependency_ready;ready_to_apply=$plan.dependency_ready;dependency_blockers=$plan.dependency_blockers;
          existing_worker_preserved=$true;bundle_worker_matches_existing=($newInventory.files.'filebridge-inbound.exe' -ceq $plan.worker_sha256);
          live_restarted=$false;network_requests=$false} | ConvertTo-Json -Depth 5 -Compress
        return
    }
    NewDirectory ([IO.Path]::GetDirectoryName($upgrade))
    NewDirectory $upgrade
    $stage=Join-Path $upgrade 'bundle'
    $stageResult=& $stageDriver -Mode Resume -SourceDirectory $bundle -StageDirectory $stage -ExpectedInventorySHA256 $ExpectedInventorySHA256 | ConvertFrom-Json
    $status=PrepareRuntime
    $plan.dependency_ready=$status.dependency_ready;$plan.dependency_blockers=$status.dependency_blockers
    $backup=Join-Path $upgrade 'plugin.before';NewDirectory $backup
    foreach ($node in @(Get-ChildItem -LiteralPath $backup -Force)) {
        if ($node.PSIsContainer -or $oldPluginNames -cnotcontains $node.Name) { throw 'CF_UPGRADE_UNKNOWN_BACKUP_ENTRY_PRESERVED' }
    }
    $candidate=Join-Path $upgrade 'config.after.yaml'
    if ($checkpoint) {
        $beforeConfig=$checkpoint.config_before_sha256;$afterConfig=$checkpoint.config_after_sha256
        $verified=ReadLocked (Join-Path $upgrade 'config.before.yaml') $beforeConfig $true
        $candidateBytes=ReadLocked $candidate $afterConfig $true
        $candidatePlan=RunPlanner
        if ($candidatePlan.config_after_sha256 -cne $afterConfig) { throw 'CF_UPGRADE_CANDIDATE_SEMANTIC_CONFLICT' }
    } else {
        $candidatePlan=RunPlanner $candidate
        $beforeConfig=$plan.config_before_sha256;$afterConfig=$candidatePlan.config_after_sha256
        if ($candidatePlan.config_before_sha256 -cne $beforeConfig) { throw 'CF_UPGRADE_CONFIG_CHANGED_DURING_PREPARE' }
        NewFile (Join-Path $upgrade 'config.before.yaml') $configBytes
        $candidateBytes=ReadLocked $candidate $afterConfig $true
    }
    foreach ($name in $oldPluginNames) {
        $destination=Join-Path $backup $name
        if (Test-Path -LiteralPath $destination) { $verified=ReadLocked $destination $originalHashes[$name] $true }
        else { NewFile $destination (ReadLocked (Join-Path $plugin $name) $originalHashes[$name] $true) }
    }
    $record=[ordered]@{schema='cf-inbound-upgrade/v1';inventory_sha256=$ExpectedInventorySHA256.ToLowerInvariant();
        previous_inventory_sha256=$previousHash;profile_sha256=(HashBytes $utf8.GetBytes($profileRoot.ToLowerInvariant()));
        upgrade_directory_sha256=(HashBytes $utf8.GetBytes($upgrade.ToLowerInvariant()));
        runtime_inventory_sha256=(HashBytes (ReadLocked (Join-Path $upgrade 'runtime.inventory.json') '' $true));
        config_before_sha256=$beforeConfig;config_after_sha256=$afterConfig}
    NewFile (Join-Path $upgrade 'upgrade.json') $utf8.GetBytes(($record | ConvertTo-Json -Compress))
    if ($Mode -in @('Apply','Resume')) {
        if (-not $plan.dependency_ready) { throw 'CF_UPGRADE_DEPENDENCIES_MISSING_NO_AUTO_INSTALL' }
        AssertStopped
        # The operator stopped Hermes. Resume accepts only pinned old/new bytes;
        # no file is deleted and the old client/worker/config references stay.
        foreach ($name in @('inbound_content.py','inbound.py','inbound_control.py','inbound_directory.py','inbound_host.py','__init__.py','plugin.yaml')) {
            $bytes=ReadLocked (Join-Path $stage ('plugin/'+$name)) $newInventory.files.PSObject.Properties['plugin/'+$name].Value $true
            $path=Join-Path $plugin $name
            if ($name -eq 'inbound_content.py') { NewFile $path $bytes }
            else { ReplaceKnown $path $bytes $originalHashes[$name] $newInventory.files.PSObject.Properties['plugin/'+$name].Value }
        }
        ReplaceKnown $config $candidateBytes $beforeConfig $afterConfig
    }
    @{ok=$true;mode=$Mode;planner_python_version=$plannerVersion;prepared=$true;applied=($Mode -in @('Apply','Resume'));existing_worker_preserved=$true;
      dependency_ready=$plan.dependency_ready;dependency_blockers=$plan.dependency_blockers;
      bundle_worker_matches_existing=($newInventory.files.'filebridge-inbound.exe' -ceq $plan.worker_sha256);
      rollback_performed=$false;live_restarted=$false;network_requests=$false} | ConvertTo-Json -Depth 5 -Compress
} finally {
    foreach ($stream in $streams.Values) { $stream.Dispose() }
    foreach ($handle in $directories.Values) { $handle.Dispose() }
}
