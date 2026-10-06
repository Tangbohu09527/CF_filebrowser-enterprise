# Windows lifecycle adapter for the audited official 0f4a98f CLI. Dot-source only.
# No process/config discovery or Hermes import occurs while loading this file.
# All public results are safe summaries. Process argv and launcher output stay in memory.
Set-StrictMode -Version 2.0
$script:CfLifecyclePlans=@{}

function New-CfLifecycleResult([bool]$Ok,[string]$Code,[string]$Id='',[object]$States=$null) {
    return [pscustomobject]@{ok=$Ok;code=$Code;plan_id=$Id;states=$States}
}
function Stop-CfLifecycleError([string]$Code) { throw $Code }
function Get-CfLifecycleError($Failure) {
    $message=$Failure.Exception.Message
    $known=@(
        'lifecycle_approval_required','lifecycle_command_timeout','lifecycle_dashboard_ownership_unproven',
        'lifecycle_dependencies_invalid','lifecycle_executor_mismatch','lifecycle_executor_unsupported',
        'lifecycle_instance_changed','lifecycle_launch_shape_unsupported','lifecycle_launcher_changed',
        'lifecycle_launcher_required','lifecycle_launcher_unsupported','lifecycle_managed_process_unsupported',
        'lifecycle_multiple_instances','lifecycle_observation_failed','lifecycle_official_version_unsupported',
        'lifecycle_output_limit','lifecycle_output_timeout','lifecycle_path_invalid','lifecycle_phase_invalid',
        'lifecycle_plan_invalid','lifecycle_profile_unsupported','lifecycle_receipt_instance_changed',
        'lifecycle_receipt_invalid','lifecycle_receipt_phase_invalid','lifecycle_reparse_refused',
        'lifecycle_resolution_failed','lifecycle_restore_failed','lifecycle_restore_instance_changed',
        'lifecycle_restore_unconfirmed','lifecycle_scheduled_task_unsupported','lifecycle_shared_profile_unsupported',
        'lifecycle_stop_failed','lifecycle_stop_not_stable','lifecycle_unknown_process','lifecycle_upgrade_not_successful'
    )
    if ($known -ccontains $message) { return $message }
    return 'lifecycle_observation_failed'
}
function Get-CfLifecycleHash([byte[]]$Bytes) {
    $hash=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() } finally { $hash.Dispose() }
}
function Get-CfLifecyclePath([string]$Path,[switch]$Existing) {
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path -match '[\x00-\x1f]' -or $Path.Substring(2).Contains(':')) { Stop-CfLifecycleError 'lifecycle_path_invalid' }
    $full=[IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($Existing) {
        $node=Get-Item -LiteralPath $full -Force -ErrorAction Stop
        while ($null -ne $node) {
            if ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) { Stop-CfLifecycleError 'lifecycle_reparse_refused' }
            $node=if ($node -is [IO.FileInfo]) {$node.Directory} else {$node.Parent}
        }
    }
    return $full
}
function Test-CfLifecycleWithin([string]$Path,[string]$Root) { return $Path.StartsWith($Root.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) }
function Get-CfLifecycleExpectedLauncher([string]$SourceRoot) {
    # This is the exact generated _launcher_script('hermes', ...) from the pinned source.
    if ($SourceRoot.Contains("'") -or $SourceRoot -match '[^\x20-\x7e]') { Stop-CfLifecycleError 'lifecycle_launcher_unsupported' }
    $literal="'"+$SourceRoot.Replace('\','\\')+"'"
    $template=@'
import os, re, sys
os.environ.pop('PYTHONHOME', None)
os.environ.pop('PYTHONPATH', None)
sys.path.insert(0, ROOT_LITERAL)
if sys.argv[1:2] == ['--print-runtime-command']: sys.dont_write_bytecode = True
from hermes_constants import get_default_hermes_root
os.environ['HERMES_HOME'] = os.environ.get('HERMES_HOME') or str(get_default_hermes_root())
if sys.argv[1:2] == ['--print-runtime-command']:
    from pathlib import Path
    from hermes_cli._launchers import print_runtime_command
    print_runtime_command(Path(ROOT_LITERAL), sys.argv[2:])
    sys.exit(0)
import hermes_bootstrap
if sys.argv[1:2] == ['--run-module']:
    import runpy
    if len(sys.argv) < 3: sys.exit('hermes: --run-module needs a module')
    module = sys.argv.pop(2)
    del sys.argv[1]
    runpy.run_module(module, run_name='__main__', alter_sys=True)
    sys.exit(0)
from hermes_cli.main import main
sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
sys.exit(main())
'@
    return $template.Replace("`r`n","`n").Replace('ROOT_LITERAL',$literal)+"`n"
}
function Get-CfLifecycleLauncherProof([string]$HermesHome,[string]$LauncherPath,[string]$SourceRoot) {
    $targetHome=Get-CfLifecyclePath $HermesHome -Existing
    $source=Get-CfLifecyclePath $SourceRoot -Existing
    $launcher=Get-CfLifecyclePath $LauncherPath -Existing
    if (-not (Test-CfLifecycleWithin $source $targetHome) -or [IO.Path]::GetFileName($launcher) -ine 'hermes.cmd') { Stop-CfLifecycleError 'lifecycle_launcher_unsupported' }
    $pins=@{
        'hermes_cli/_launchers.py'='d6fc90ff21944378cd3c1a08467693e5e9ae920eeb617ca5fe9b6d1059d1335b'
        'hermes_cli/gateway.py'='3a50821d3ccd3a2d9426b3b9a126ea049cd15657be42fd3e1a838fd89a19972c'
        'hermes_cli/gateway_windows.py'='1b44f212e55ab40d009d17395ad8b01303739f3d660675492ff6f0ecd5da4e81'
        'hermes_cli/main.py'='fae488b821bc41623d17c2a08c8ac35b15d138ef96f92cd2e6fc5d171a9e4807'
        'hermes_cli/main_dashboard.py'='c7ecfb6a6b1324035e5ac9eba10a701e06631029d5e4bab246b1f5755fdc1327'
        'hermes_cli/dashboard_procs.py'='50ac675d117076d584ce0b96ead0ee2564195a6f9997683590695d5ba614247a'
        'hermes_cli/subcommands/dashboard.py'='cf78789c16e5b2e2183671711944cc230bda241726ca3420a4c0b519f7fc4193'
        'hermes_cli/gateway_profile_lifecycle.py'='e6953b4b98c843cf02c799a23fdb73c8104cd15fa0e213e61744beb66c8b3a1b'
        'gateway/status.py'='75f6a0139123686a2081c0577dd928c205c0cb9daff64e5b8d646e8397fa2045'
    }
    foreach ($name in $pins.Keys) {
        $path=Get-CfLifecyclePath (Join-Path $source $name) -Existing
        if ((Get-Item -LiteralPath $path).Length -gt 2097152 -or (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $pins[$name]) { Stop-CfLifecycleError 'lifecycle_official_version_unsupported' }
    }
    if ((Get-Item -LiteralPath $launcher).Length -gt 16384) { Stop-CfLifecycleError 'lifecycle_launcher_unsupported' }
    $bytes=[IO.File]::ReadAllBytes($launcher);$text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
    $pattern='\A@echo off\r?\n"([^"\r\n]+)" -I -c "import base64; exec\(base64\.b64decode\(''([A-Za-z0-9+/=]+)''\)\)" %\*\r?\n?\z'
    $match=[regex]::Match($text,$pattern)
    if (-not $match.Success) { Stop-CfLifecycleError 'lifecycle_launcher_unsupported' }
    $python=Get-CfLifecyclePath $match.Groups[1].Value -Existing
    if (-not (Test-CfLifecycleWithin $python $targetHome) -or [IO.Path]::GetFileName($python) -ine 'python.exe') { Stop-CfLifecycleError 'lifecycle_executor_unsupported' }
    $encoded=$match.Groups[2].Value
    $decoded=[Text.UTF8Encoding]::new($false,$true).GetString([Convert]::FromBase64String($encoded))
    if ($decoded -cne (Get-CfLifecycleExpectedLauncher $source)) { Stop-CfLifecycleError 'lifecycle_launcher_unsupported' }
    return @{launcher=$launcher;launcher_sha256=(Get-CfLifecycleHash $bytes);source_root=$source;python=$python;
        python_sha256=(Get-FileHash -LiteralPath $python -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant();
        source_commit='0f4a98f87c17007b81500239d0bd5b9574027b73';code=("import base64; exec(base64.b64decode('"+$encoded+"'))");home=$targetHome}
}
function Initialize-CfLifecycleNative {
    if ('CfFileBridge.LifecycleArgvV1' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
namespace CfFileBridge { public static class LifecycleArgvV1 {
 [DllImport("shell32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CommandLineToArgvW(string s, out int n);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
 public static string[] Parse(string s) { int n; var p=CommandLineToArgvW(s,out n); if(p==IntPtr.Zero) throw new InvalidOperationException();
  try { if(n>128) throw new InvalidOperationException(); var a=new string[n]; for(int i=0;i<n;i++) a[i]=Marshal.PtrToStringUni(Marshal.ReadIntPtr(p,i*IntPtr.Size)); return a; } finally {LocalFree(p);} }
 public static Task<string> Capture(TextReader reader) { return Task.Run(() => { var result=new StringBuilder(); var buffer=new char[2048]; int n; bool excess=false;
  while((n=reader.Read(buffer,0,buffer.Length))!=0) { if(result.Length+n<=65536) result.Append(buffer,0,n); else excess=true; }
  if(excess) throw new IOException("lifecycle_output_limit"); return result.ToString(); }); }
} }
'@
}
function Get-CfLifecycleRestoreArgs([string[]]$InputArgs) {
    if ($InputArgs.Count -eq 2 -and $InputArgs[0] -ceq 'gateway' -and $InputArgs[1] -ceq 'run') { return ,@('gateway','start') }
    # No inferred port/defaults: require every endpoint argument explicitly present.
    if ($InputArgs.Count -ne 7 -or $InputArgs[0] -cne 'dashboard' -or $InputArgs[1] -cne '--no-open' -or $InputArgs[2] -cne '--host' -or
        $InputArgs[3] -cne '127.0.0.1' -or $InputArgs[4] -cne '--port' -or $InputArgs[5] -notmatch '^[1-9][0-9]{0,4}$' -or
        [int]$InputArgs[5] -gt 65535 -or $InputArgs[6] -cne '--skip-build') { Stop-CfLifecycleError 'lifecycle_launch_shape_unsupported' }
    return ,@($InputArgs)
}
function Test-CfLifecycleGatewayRecord($Row,[string]$HermesHome) {
    # Fixed gateway/status.py records both files, including the owner's HOME and
    # a Windows centisecond process fingerprint. Never import the official module.
    $expected=[Math]::Round((([DateTime]$Row.CreationDate).ToUniversalTime()-[DateTime]::SpecifyKind([DateTime]'1970-01-01',[DateTimeKind]::Utc)).TotalSeconds*100,0,[MidpointRounding]::ToEven)
    foreach($name in @('gateway.pid','gateway.lock')) {
        $path=Get-CfLifecyclePath (Join-Path $HermesHome $name) -Existing
        $node=Get-Item -LiteralPath $path -Force
        if ($node.PSIsContainer -or $node.Length -gt 65536) {return $false}
        $reader=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try {
            $bytes=[byte[]]::new(65537);$used=0
            do {$n=$reader.Read($bytes,$used,$bytes.Length-$used);$used+=$n} while($n -gt 0 -and $used -lt $bytes.Length)
            if ($used -gt 65536) {return $false}
            $record=[Text.UTF8Encoding]::new($false,$true).GetString($bytes,0,$used) | ConvertFrom-Json
        } finally {$reader.Dispose()}
        if ($record.kind -cne 'hermes-gateway' -or $record.pid -is [bool] -or $record.start_time -is [bool] -or
            $record.pid -isnot [ValueType] -or $record.start_time -isnot [ValueType] -or
            $record.pid -ne $Row.ProcessId -or $record.start_time -ne $expected -or
            (Get-CfLifecyclePath ([string]$record.hermes_home)) -ine $HermesHome) {return $false}
    }
    $stream=[IO.FileStream]::new((Join-Path $HermesHome 'gateway.lock'),[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        try {$stream.Lock(1048576,1);$stream.Unlock(1048576,1);return $false}
        catch [IO.IOException] {if (($_.Exception.HResult -band 65535) -eq 33) {return $true};throw}
    } finally {$stream.Dispose()}
}
function Get-CfLifecycleSnapshot([string]$HermesHome,[string]$Profile) {
    $targetHome=Get-CfLifecyclePath $HermesHome -Existing
    if ($Profile -cne 'default') { Stop-CfLifecycleError 'lifecycle_profile_unsupported' }
    $named=Join-Path $targetHome 'profiles'
    if ((Test-Path -LiteralPath $named) -and @(Get-ChildItem -LiteralPath $named -Force -Directory).Count -gt 0) { Stop-CfLifecycleError 'lifecycle_shared_profile_unsupported' }
    Initialize-CfLifecycleNative
    $rows=@(Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,CreationDate,ExecutablePath,CommandLine -ErrorAction Stop)
    $services=@(Get-CimInstance Win32_Service -Property ProcessId -ErrorAction Stop)
    $tasks=@(Get-ScheduledTask -ErrorAction Stop | Where-Object {
        $_.TaskName -like 'Hermes*' -or @($_.Actions | Where-Object {
            $executeProperty=$_.PSObject.Properties['Execute'];$argumentsProperty=$_.PSObject.Properties['Arguments']
            ($null -ne $executeProperty -and ([string]$executeProperty.Value).IndexOf($targetHome,[StringComparison]::OrdinalIgnoreCase) -ge 0) -or
            ($null -ne $argumentsProperty -and ([string]$argumentsProperty.Value).IndexOf($targetHome,[StringComparison]::OrdinalIgnoreCase) -ge 0)
        }).Count -gt 0
    })
    $found=@();$unknown=@();$ownSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($row in $rows) {
        $exe=[string]$row.ExecutablePath;$command=[string]$row.CommandLine
        $inside=$exe -and (Test-CfLifecycleWithin $exe $targetHome)
        $looks=$command -match '(?i)(?:hermes|hermes_cli)[^\r\n]*(?:gateway|dashboard|serve)'
        if (-not $looks -and -not ($inside -and [IO.Path]::GetFileName($exe) -match '^pythonw?\.exe$')) { continue }
        if (-not $inside -or -not $command -or $command.Length -gt 32768) { $unknown+='unproven_process';continue }
        $argv=@([CfFileBridge.LifecycleArgvV1]::Parse($command))
        if ($argv.Count -lt 5 -or $argv[0] -ine $exe -or $argv[1] -cne '-m' -or $argv[2] -cne 'hermes_cli.main') { $unknown+='unproven_launch';continue }
        $tail=@($argv[3..($argv.Count-1)])
        if ($tail[0] -cin @('-p','--profile')) {
            if ($tail.Count -lt 4 -or $tail[1] -cne $Profile) {$unknown+='unproven_profile';continue}
            $tail=@($tail[2..($tail.Count-1)])
        }
        # No equivalent narrowly scoped dashboard ownership record has been
        # established here. Never infer its HOME or restore Desktop/serve argv.
        if ($tail[0] -cne 'gateway') {$unknown+='dashboard_ownership_unproven';continue}
        try {if (-not (Test-CfLifecycleGatewayRecord $row $targetHome)) {$unknown+='unproven_gateway_record';continue}} catch {$unknown+='unproven_gateway_record';continue}
        try { $restore=Get-CfLifecycleRestoreArgs $tail } catch { $unknown+='unsupported_launch';continue }
        $owner=Invoke-CimMethod -InputObject $row -MethodName GetOwnerSid -ErrorAction Stop
        if ($owner.ReturnValue -ne 0 -or $owner.Sid -cne $ownSid -or $null -eq $row.CreationDate) { $unknown+='unproven_owner';continue }
        $parent=@($rows | Where-Object ProcessId -eq $row.ParentProcessId)
        $managed=@($services | Where-Object { $_.ProcessId -eq $row.ProcessId -or $_.ProcessId -eq $row.ParentProcessId }).Count -gt 0
        if ($parent.Count -gt 1 -or ($parent.Count -eq 1 -and (-not $parent[0].ExecutablePath -or [IO.Path]::GetFileName([string]$parent[0].ExecutablePath) -match '(?i)^(services|svchost|taskeng|taskhostw|hermes|hermes-desktop)\.exe$'))) { $managed=$true }
        $found+=@{pid=[int]$row.ProcessId;identity=([DateTime]$row.CreationDate).ToUniversalTime().Ticks.ToString();
            kind=$tail[0];executable=(Get-CfLifecyclePath $exe -Existing);owned=$true;managed=$managed;shared=$false;restore_args=@($restore)}
    }
    return @{processes=@($found);tasks=@($tasks | ForEach-Object {$_.TaskName});unknown=@($unknown)}
}
function ConvertTo-CfLifecycleQuotedArg([string]$Value) {
    # CommandLineToArgvW/MS C runtime quoting; never sent through cmd.exe.
    return '"'+[regex]::Replace([regex]::Replace($Value,'(\\*)"','$1$1\"'),'(\\+)$','$1$1')+'"'
}
function Invoke-CfLifecycleOfficial($Proof,[string]$Operation,[string[]]$Arguments) {
    if ((Get-FileHash -LiteralPath $Proof.launcher -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $Proof.launcher_sha256 -or
        (Get-FileHash -LiteralPath $Proof.python -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $Proof.python_sha256) { Stop-CfLifecycleError 'lifecycle_launcher_changed' }
    $tail=@('--profile','default')+@($Arguments)
    if ($Operation -ceq 'resolve') { $tail=@('--print-runtime-command','--')+$tail }
    $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$Proof.python
    $start.Arguments=((@('-I','-B','-c',$Proof.code)+$tail | ForEach-Object {ConvertTo-CfLifecycleQuotedArg $_}) -join ' ')
    $start.WorkingDirectory=$Proof.source_root;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.EnvironmentVariables['HERMES_HOME']=$Proof.home
    $start.EnvironmentVariables['HERMES_GATEWAY_INSTALL_START_ON_LOGIN']='false'
    $start.EnvironmentVariables['PYTHONDONTWRITEBYTECODE']='1'
    foreach($key in @('PYTHONHOME','PYTHONPATH','VIRTUAL_ENV','HERMES_PROFILE','HERMES_DESKTOP','HERMES_UPDATE_POST_SWAP')) { $start.EnvironmentVariables.Remove($key) }
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $process=[Diagnostics.Process]::Start($start);$process.StandardInput.Close()
    # Drain both pipes with a strict memory cap, without displaying private output.
    Initialize-CfLifecycleNative
    $stdout=[CfFileBridge.LifecycleArgvV1]::Capture($process.StandardOutput);$stderr=[CfFileBridge.LifecycleArgvV1]::Capture($process.StandardError)
    if ($Operation -ceq 'start' -and $Arguments[0] -ceq 'dashboard') {
        # Official dashboard is a foreground server. Keep these in-memory drains alive.
        return @{exit_code=0;stdout='';pid=$process.Id;process=$process;stdout_task=$stdout;stderr_task=$stderr}
    }
    try {
        if (-not $process.WaitForExit(45000)) { Stop-CfLifecycleError 'lifecycle_command_timeout' }
        if (-not $stdout.Wait(2000) -or -not $stderr.Wait(2000)) { Stop-CfLifecycleError 'lifecycle_output_timeout' }
        if ($stdout.Result.Length -gt 65536 -or $stderr.Result.Length -gt 65536) { Stop-CfLifecycleError 'lifecycle_output_limit' }
        return @{exit_code=$process.ExitCode;stdout=$stdout.Result;pid=$process.Id}
    } finally { $process.Dispose() }
}
function Get-CfLifecycleDependencies([hashtable]$Dependencies) {
    if ($null -ne $Dependencies) {
        foreach ($key in @('Inspect','Snapshot','Run','Sleep','Monotonic')) { if (-not $Dependencies.ContainsKey($key) -or $Dependencies[$key] -isnot [scriptblock]) { Stop-CfLifecycleError 'lifecycle_dependencies_invalid' } }
        return $Dependencies
    }
    return @{Inspect={param($h,$l,$s) Get-CfLifecycleLauncherProof $h $l $s};Snapshot={param($h,$p) Get-CfLifecycleSnapshot $h $p};
        Run={param($p,$o,$a) Invoke-CfLifecycleOfficial $p $o $a};Sleep={param($s) Start-Sleep -Milliseconds ([int]($s*1000))};
        Monotonic={return [double][Diagnostics.Stopwatch]::GetTimestamp()/[Diagnostics.Stopwatch]::Frequency}}
}
function Assert-CfLifecycleSnapshot($Snapshot) {
    if (@($Snapshot.tasks).Count) { Stop-CfLifecycleError 'lifecycle_scheduled_task_unsupported' }
    if (@($Snapshot.unknown) -ccontains 'dashboard_ownership_unproven') {Stop-CfLifecycleError 'lifecycle_dashboard_ownership_unproven'}
    if (@($Snapshot.unknown).Count) { Stop-CfLifecycleError 'lifecycle_unknown_process' }
    foreach($p in @($Snapshot.processes)) {
        if (-not $p.owned) { Stop-CfLifecycleError 'lifecycle_unknown_process' }
        if ($p.managed) { Stop-CfLifecycleError 'lifecycle_managed_process_unsupported' }
        if ($p.shared) { Stop-CfLifecycleError 'lifecycle_shared_profile_unsupported' }
        if ($p.kind -cnotin @('gateway','dashboard')) { Stop-CfLifecycleError 'lifecycle_launch_shape_unsupported' }
        $callArgs=@($p.restore_args);if ($p.kind -ceq 'gateway') {if (($callArgs -join '|') -cne 'gateway|start') {Stop-CfLifecycleError 'lifecycle_launch_shape_unsupported'}} else {Get-CfLifecycleRestoreArgs $callArgs | Out-Null}
    }
    foreach($kind in @('gateway','dashboard')) { if (@($Snapshot.processes | Where-Object kind -ceq $kind).Count -gt 1) { Stop-CfLifecycleError 'lifecycle_multiple_instances' } }
}
function Get-CfLifecyclePrivate($Plan) {
    if (-not $Plan.ok -or -not $script:CfLifecyclePlans.ContainsKey([string]$Plan.plan_id)) { Stop-CfLifecycleError 'lifecycle_plan_invalid' }
    return $script:CfLifecyclePlans[[string]$Plan.plan_id]
}
function Get-CfLifecycleIdentities($Processes) { return (@($Processes | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.kind,$_.pid,$_.identity,$_.executable } | Sort-Object) -join "`n") }
function Get-FileBridgeLifecyclePlan {
    [CmdletBinding()]param([Parameter(Mandatory=$true)][string]$HermesHome,[string]$Profile='default',[string]$LauncherPath='',[string]$SourceRoot='',[hashtable]$Dependencies)
    try {
        if ($Profile -cne 'default') { Stop-CfLifecycleError 'lifecycle_profile_unsupported' }
        $targetHome=Get-CfLifecyclePath $HermesHome;$deps=Get-CfLifecycleDependencies $Dependencies
        $snapshot=& $deps.Snapshot $targetHome $Profile;Assert-CfLifecycleSnapshot $snapshot
        $proof=$null;$states=@{gateway='stopped';dashboard='stopped'}
        if (@($snapshot.processes).Count) {
            if (-not $LauncherPath) { Stop-CfLifecycleError 'lifecycle_launcher_required' }
            if (-not $SourceRoot) {$SourceRoot=Join-Path $targetHome 'hermes-agent'}
            $proof=& $deps.Inspect $targetHome $LauncherPath $SourceRoot
            foreach($p in @($snapshot.processes)) { if ($p.executable -ine $proof.python) {Stop-CfLifecycleError 'lifecycle_executor_mismatch'};$states[$p.kind]='running' }
        }
        $id=[Guid]::NewGuid().ToString('N')
        $script:CfLifecyclePlans[$id]=@{home=$targetHome;profile=$Profile;proof=$proof;original=@($snapshot.processes);states=$states;dependencies=$deps;phase='planned';runtime=@{}}
        return New-CfLifecycleResult $true 'lifecycle_planned' $id $states.Clone()
    } catch { return New-CfLifecycleResult $false (Get-CfLifecycleError $_) }
}
function Wait-CfLifecycleStopped($Private) {
    $deps=$Private.dependencies;$since=$null
    do {
        $snapshot=& $deps.Snapshot $Private.home $Private.profile;Assert-CfLifecycleSnapshot $snapshot
        if (@($snapshot.processes).Count) { Stop-CfLifecycleError 'lifecycle_stop_not_stable' }
        $now=& $deps.Monotonic
        if ($null -eq $since) {$since=$now}
        if (($now-$since) -ge 10.0) { return }
        & $deps.Sleep 1.0
    } while ($true)
}
function Stop-FileBridgeLifecycle {
    [CmdletBinding()]param([Parameter(Mandatory=$true)]$Plan,[switch]$Approved)
    $private=$null
    try {
        $private=Get-CfLifecyclePrivate $Plan
        if (-not $Approved) { Stop-CfLifecycleError 'lifecycle_approval_required' }
        if ($private.phase -ceq 'stopped') {Wait-CfLifecycleStopped $private;return New-CfLifecycleResult $true 'lifecycle_stopped' $Plan.plan_id $private.states.Clone()}
        if ($private.phase -cne 'planned') { Stop-CfLifecycleError 'lifecycle_phase_invalid' }
        $deps=$private.dependencies;$current=& $deps.Snapshot $private.home $private.profile;Assert-CfLifecycleSnapshot $current
        if ((Get-CfLifecycleIdentities $current.processes) -cne (Get-CfLifecycleIdentities $private.original)) {Stop-CfLifecycleError 'lifecycle_instance_changed'}
        if (@($private.original).Count) {
            $proof=& $deps.Inspect $private.home $private.proof.launcher $private.proof.source_root
            if ($proof.launcher_sha256 -cne $private.proof.launcher_sha256 -or $proof.python_sha256 -cne $private.proof.python_sha256) {Stop-CfLifecycleError 'lifecycle_launcher_changed'}
            # Authorization precedes this first official import. Returned bootstrap stays private.
            foreach($p in $private.original) {
                $resolved=& $deps.Run $proof 'resolve' @($p.restore_args)
                if ($resolved.exit_code -ne 0 -or $resolved.stdout.Length -gt 65536) {Stop-CfLifecycleError 'lifecycle_resolution_failed'}
                $argv=$resolved.stdout | ConvertFrom-Json
                if ($argv -isnot [array] -or $argv.Count -lt 4 -or $argv[0] -ine $proof.python -or $argv[1] -cne '-I' -or $argv[2] -cne '-c') {Stop-CfLifecycleError 'lifecycle_executor_mismatch'}
                $private.runtime[$p.kind]=@($argv)
            }
            # The CLI resolves again at execution; recheck ownership after resolution imports.
            $current=& $deps.Snapshot $private.home $private.profile;Assert-CfLifecycleSnapshot $current
            if ((Get-CfLifecycleIdentities $current.processes) -cne (Get-CfLifecycleIdentities $private.original)) {Stop-CfLifecycleError 'lifecycle_instance_changed'}
            foreach($kind in @('gateway','dashboard')) {
                if ($private.states[$kind] -ceq 'running') {
                    $callArgs=if($kind -ceq 'gateway'){@('gateway','stop')}else{@('dashboard','--stop')}
                    $result=& $deps.Run $proof 'stop' $callArgs
                    if ($result.exit_code -ne 0) {Stop-CfLifecycleError 'lifecycle_stop_failed'}
                }
            }
        }
        Wait-CfLifecycleStopped $private;$private.phase='stopped'
        return New-CfLifecycleResult $true 'lifecycle_stopped' $Plan.plan_id $private.states.Clone()
    } catch { if ($null -ne $private -and $Approved) {$private.phase='failed'};return New-CfLifecycleResult $false (Get-CfLifecycleError $_) }
}
function Restore-FileBridgeLifecycle {
    [CmdletBinding()]param([Parameter(Mandatory=$true)]$Plan,[switch]$UpgradeSucceeded)
    $private=$null
    try {
        $private=Get-CfLifecyclePrivate $Plan
        if (-not $UpgradeSucceeded) {Stop-CfLifecycleError 'lifecycle_upgrade_not_successful'}
        if ($private.phase -ceq 'restored') {
            $observed=& $private.dependencies.Snapshot $private.home $private.profile;Assert-CfLifecycleSnapshot $observed
            if ((Get-CfLifecycleIdentities $observed.processes) -cne $private.restored_identities) {Stop-CfLifecycleError 'lifecycle_restore_instance_changed'}
            return New-CfLifecycleResult $true 'lifecycle_restored' $Plan.plan_id $private.states.Clone()
        }
        if ($private.phase -ceq 'planned' -and @($private.original).Count -eq 0) {$private.phase='stopped'}
        if ($private.phase -cne 'stopped') {Stop-CfLifecycleError 'lifecycle_phase_invalid'}
        Wait-CfLifecycleStopped $private;$deps=$private.dependencies
        if (@($private.original).Count) {
            $proof=& $deps.Inspect $private.home $private.proof.launcher $private.proof.source_root
            if ($proof.launcher_sha256 -cne $private.proof.launcher_sha256 -or $proof.python_sha256 -cne $private.proof.python_sha256) {Stop-CfLifecycleError 'lifecycle_launcher_changed'}
            foreach($p in $private.original) {
                $result=& $deps.Run $proof 'start' @($p.restore_args)
                if ($result.exit_code -ne 0) {Stop-CfLifecycleError 'lifecycle_restore_failed'}
                $private.runtime['started_'+$p.kind]=$result
                & $deps.Sleep 2.0
                $observed=& $deps.Snapshot $private.home $private.profile;Assert-CfLifecycleSnapshot $observed
                $match=@($observed.processes | Where-Object {$_.kind -ceq $p.kind -and $_.executable -ieq $proof.python})
                if ($match.Count -ne 1) {Stop-CfLifecycleError 'lifecycle_restore_unconfirmed'}
            }
        }
        $final=& $deps.Snapshot $private.home $private.profile;Assert-CfLifecycleSnapshot $final
        $expectedKinds=@($private.original | ForEach-Object {$_.kind} | Sort-Object) -join '|'
        $actualKinds=@($final.processes | ForEach-Object {$_.kind} | Sort-Object) -join '|'
        if ($actualKinds -cne $expectedKinds) {Stop-CfLifecycleError 'lifecycle_restore_unconfirmed'}
        $private.restored_identities=Get-CfLifecycleIdentities $final.processes
        $private.phase='restored';return New-CfLifecycleResult $true 'lifecycle_restored' $Plan.plan_id $private.states.Clone()
    } catch {if ($null -ne $private -and $UpgradeSucceeded) {$private.phase='failed'};return New-CfLifecycleResult $false (Get-CfLifecycleError $_)}
}
function Export-FileBridgeLifecycleReceipt {
    [CmdletBinding()]param([Parameter(Mandatory=$true)]$Plan)
    $private=Get-CfLifecyclePrivate $Plan
    if ($private.phase -cnotin @('planned','stopped')) {Stop-CfLifecycleError 'lifecycle_receipt_phase_invalid'}
    $proof=$null
    if ($null -ne $private.proof) {$proof=@{};foreach($key in @('launcher','launcher_sha256','source_root','python','python_sha256','source_commit')) {$proof[$key]=$private.proof[$key]}}
    $original=@($private.original | ForEach-Object {@{kind=$_.kind;restore_args=@($_.restore_args);pid=$_.pid;identity=$_.identity;executable=$_.executable}})
    # Caller persists these bytes with a protected DACL and stores the digest in its protected transaction receipt.
    $receipt=@{schema='cf-filebridge-lifecycle/v1';home=$private.home;profile=$private.profile;phase=$private.phase;proof=$proof;original=$original} | ConvertTo-Json -Compress -Depth 6
    if ($receipt.Length -gt 16384) {Stop-CfLifecycleError 'lifecycle_receipt_invalid'}
    return $receipt
}
function Import-FileBridgeLifecycleReceipt {
    [CmdletBinding()]param([Parameter(Mandatory=$true)][string]$Receipt,[Parameter(Mandatory=$true)][string]$ExpectedSHA256,
        [Parameter(Mandatory=$true)][string]$HermesHome,[string]$Profile='default',[hashtable]$Dependencies)
    try {
        if ($Receipt.Length -gt 16384 -or $ExpectedSHA256 -cnotmatch '^[0-9a-f]{64}$' -or (Get-CfLifecycleHash ([Text.Encoding]::UTF8.GetBytes($Receipt))) -cne $ExpectedSHA256) {Stop-CfLifecycleError 'lifecycle_receipt_invalid'}
        $r=$Receipt|ConvertFrom-Json
        if (@($r.PSObject.Properties.Name).Count -ne 6 -or $r.schema -cne 'cf-filebridge-lifecycle/v1' -or $r.phase -cnotin @('planned','stopped') -or $r.home -ine (Get-CfLifecyclePath $HermesHome) -or $r.profile -cne $Profile -or $Profile -cne 'default') {Stop-CfLifecycleError 'lifecycle_receipt_invalid'}
        $deps=Get-CfLifecycleDependencies $Dependencies;$snapshot=& $deps.Snapshot $r.home $Profile;Assert-CfLifecycleSnapshot $snapshot
        $states=@{gateway='stopped';dashboard='stopped'};$original=@();$proof=$null
        if (@($r.original).Count -gt 2) {Stop-CfLifecycleError 'lifecycle_receipt_invalid'}
        foreach($p in @($r.original)) {
            if (@($p.PSObject.Properties.Name).Count -ne 5 -or $p.kind -cnotin @('gateway','dashboard') -or $states[$p.kind] -cne 'stopped' -or
                $p.pid -is [bool] -or $p.pid -isnot [ValueType] -or $p.pid -le 0 -or $p.identity -isnot [string] -or $p.identity -notmatch '^[A-Za-z0-9-]{1,80}$' -or $p.executable -isnot [string]) {Stop-CfLifecycleError 'lifecycle_receipt_invalid'}
            $callArgs=@($p.restore_args);if ($p.kind -ceq 'gateway') {if(($callArgs -join '|') -cne 'gateway|start'){Stop-CfLifecycleError 'lifecycle_receipt_invalid'}}else{Get-CfLifecycleRestoreArgs $callArgs|Out-Null}
            $states[$p.kind]='running';$original+=@{kind=$p.kind;restore_args=$callArgs;pid=$p.pid;identity=$p.identity;executable=(Get-CfLifecyclePath $p.executable)}
        }
        if ($original.Count) {
            $proof=& $deps.Inspect $r.home $r.proof.launcher $r.proof.source_root
            foreach($key in @('launcher','launcher_sha256','source_root','python','python_sha256','source_commit')) {if($proof[$key] -cne $r.proof.$key){Stop-CfLifecycleError 'lifecycle_launcher_changed'}}
        } elseif ($null -ne $r.proof) {Stop-CfLifecycleError 'lifecycle_receipt_invalid'}
        $phase='stopped'
        if (@($snapshot.processes).Count) {
            if ($r.phase -cne 'planned' -or (Get-CfLifecycleIdentities $snapshot.processes) -cne (Get-CfLifecycleIdentities $original)) {Stop-CfLifecycleError 'lifecycle_receipt_instance_changed'}
            $phase='planned'
        }
        $id=[Guid]::NewGuid().ToString('N');$script:CfLifecyclePlans[$id]=@{home=$r.home;profile=$Profile;proof=$proof;original=$original;states=$states;dependencies=$deps;phase=$phase;runtime=@{}}
        return New-CfLifecycleResult $true 'lifecycle_receipt_loaded' $id $states.Clone()
    } catch {return New-CfLifecycleResult $false (Get-CfLifecycleError $_)}
}
