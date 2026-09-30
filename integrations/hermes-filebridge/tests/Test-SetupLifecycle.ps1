# Synthetic lifecycle observations only: never query or launch an installed Hermes.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {throw 'Native Windows PowerShell 5.1 required.'}
$module=Join-Path $PSScriptRoot '../windows/Setup-Lifecycle.ps1'
if (-not (Test-Path -LiteralPath $module)) { throw 'TEST_FAILED: lifecycle module missing' }
. $module
$script:cases=0
function Require([bool]$Value,[string]$Message) { if (-not $Value) { throw ('TEST_FAILED: '+$Message) } }
function NewFixture {
    $s=@{clock=0.0;calls=[Collections.Generic.List[object]]::new();processes=@();tasks=@();unknown=@();resolveMismatch=$false;stopFails=$false;respawn=$false;inspectCalls=0}
    $proof=@{launcher='C:\synthetic\hermes.cmd';launcher_sha256=('a'*64);source_root='C:\synthetic\home\hermes-agent';python='C:\synthetic\home\tools\python.exe';python_sha256=('b'*64);source_commit='0f4a98f87c17007b81500239d0bd5b9574027b73'}
    $deps=@{
        Inspect={param($home,$launcher,$source) $s.inspectCalls++; return $proof}.GetNewClosure()
        Snapshot={param($home,$profile) return @{processes=@($s.processes);tasks=@($s.tasks);unknown=@($s.unknown)}}.GetNewClosure()
        Run={param($p,$operation,$arguments)
            $s.calls.Add(@{operation=$operation;arguments=@($arguments)})
            if ($operation -eq 'resolve') {
                $exe=if ($s.resolveMismatch) {'C:\other\python.exe'} else {$proof.python}
                return @{exit_code=0;stdout=(ConvertTo-Json -Compress -InputObject (@($exe,'-I','-c','synthetic bootstrap')+@($arguments)) -Depth 4);pid=0}
            }
            if ($operation -eq 'stop') {
                if ($s.stopFails) { return @{exit_code=1;stdout='synthetic-secret-output';pid=0} }
                $s.processes=@();return @{exit_code=0;stdout='synthetic-secret-output';pid=0}
            }
            if ($operation -eq 'start') {
                $kind=if ($arguments -contains 'gateway') {'gateway'} else {'dashboard'}
                $s.processes+=NewProcess $kind 99
                return @{exit_code=0;stdout='synthetic-secret-output';pid=99}
            }
            throw 'TEST_FAILED: unrecognized operation'
        }.GetNewClosure()
        Sleep={param($seconds) $s.clock+=$seconds; if ($s.respawn) {$s.processes=@(NewProcess 'gateway' 77)}}.GetNewClosure()
        Monotonic={return [double]$s.clock}.GetNewClosure()
    }
    return @{state=$s;dependencies=$deps;proof=$proof}
}
function NewProcess([string]$Kind='gateway',[int]$Number=31) {
    return @{pid=$Number;identity=('start-'+$Number);kind=$Kind;executable='C:\synthetic\home\tools\python.exe';
        owned=$true;managed=$false;shared=$false;restore_args=$(if($Kind -eq 'gateway'){@('gateway','start')}else{@('dashboard','--no-open','--host','127.0.0.1','--port','9119','--skip-build')})}
}
function Plan($f) { return Get-FileBridgeLifecyclePlan -HermesHome 'C:\synthetic\home' -Profile default -LauncherPath $f.proof.launcher -Dependencies $f.dependencies }
function Case([string]$Name,[scriptblock]$Body) { & $Body; $script:cases++;Write-Output ('SETUP_LIFECYCLE_CASE='+$Name+':PASS') }
function ReceiptHash([string]$Text) {return Get-CfLifecycleHash ([Text.Encoding]::UTF8.GetBytes($Text))}
Case 'stopped-never-resolves-or-starts' {
    $f=NewFixture;$p=Plan $f;Require $p.ok 'plan';Require ((Stop-FileBridgeLifecycle -Plan $p -Approved).ok) 'stopped stop'
    Require ((Restore-FileBridgeLifecycle -Plan $p -UpgradeSucceeded).ok) 'stopped restore';Require ($f.state.calls.Count -eq 0) 'no commands';Require ($f.state.inspectCalls -eq 0) 'no launcher import/discovery'
}
Case 'approval-required-before-runtime-resolution' {
    $f=NewFixture;$f.state.processes=@(NewProcess);$p=Plan $f;$r=Stop-FileBridgeLifecycle -Plan $p
    Require ($r.code -eq 'lifecycle_approval_required') 'approval';Require ($f.state.calls.Count -eq 0) 'no command'
}
Case 'stop-ten-seconds-and-restore-original-running' {
    $f=NewFixture;$f.state.processes=@(NewProcess);$p=Plan $f;Require $p.ok 'running plan';$r=Stop-FileBridgeLifecycle -Plan $p -Approved
    Require $r.ok ('stopped: '+$r.code);Require ($f.state.clock -ge 10) 'ten continuous seconds';Require ((Restore-FileBridgeLifecycle -Plan $p -UpgradeSucceeded).ok) 'restore'
    Require (@($f.state.calls|Where-Object operation -eq 'start').Count -eq 1) 'only one original component';Require (($r|ConvertTo-Json -Depth 6) -notmatch 'synthetic-secret-output|bootstrap|python.exe') 'safe result'
}
foreach($flag in @('managed','shared')) { $name=$flag;Case ('refuse-'+$flag) { $f=NewFixture;$q=NewProcess;$q[$name]=$true;$f.state.processes=@($q);$p=Plan $f;Require (-not $p.ok) 'blocked';Require ($f.state.calls.Count -eq 0) 'no command' }.GetNewClosure() }
Case 'unknown-gateway-refused' {$f=NewFixture;$f.state.unknown=@('foreign_gateway');$p=Plan $f;Require ($p.code -eq 'lifecycle_unknown_process') 'unknown';Require ($f.state.calls.Count -eq 0) 'no command'}
Case 'scheduled-task-refused' {$f=NewFixture;$f.state.tasks=@('Hermes_Gateway');$p=Plan $f;Require ($p.code -eq 'lifecycle_scheduled_task_unsupported') 'task';Require ($f.state.calls.Count -eq 0) 'no command'}
Case 'identity-change-before-stop-refused' {$f=NewFixture;$f.state.processes=@(NewProcess);$p=Plan $f;$f.state.processes=@(NewProcess 'gateway' 42);$r=Stop-FileBridgeLifecycle -Plan $p -Approved;Require ($r.code -eq 'lifecycle_instance_changed') 'identity';Require ($f.state.calls.Count -eq 0) 'no command'}
Case 'runtime-executor-mismatch-refused-before-stop' {$f=NewFixture;$f.state.processes=@(NewProcess);$p=Plan $f;$f.state.resolveMismatch=$true;$r=Stop-FileBridgeLifecycle -Plan $p -Approved;Require ($r.code -eq 'lifecycle_executor_mismatch') 'executor';Require (@($f.state.calls|Where-Object operation -eq 'stop').Count -eq 0) 'not stopped'}
Case 'respawn-prevents-install-and-restore' {$f=NewFixture;$f.state.processes=@(NewProcess);$p=Plan $f;$f.state.respawn=$true;$r=Stop-FileBridgeLifecycle -Plan $p -Approved;Require (-not $r.ok) 'not steady';Require (-not (Restore-FileBridgeLifecycle -Plan $p -UpgradeSucceeded).ok) 'no mixed start';Require (@($f.state.calls|Where-Object operation -eq 'start').Count -eq 0) 'never start'}
Case 'stop-failure-private-output-and-no-restore' {$f=NewFixture;$f.state.processes=@(NewProcess);$p=Plan $f;$f.state.stopFails=$true;$r=Stop-FileBridgeLifecycle -Plan $p -Approved;Require ($r.code -eq 'lifecycle_stop_failed') 'stop code';Require (($r|ConvertTo-Json) -notmatch 'synthetic-secret') 'secret absent';Require (-not (Restore-FileBridgeLifecycle -Plan $p -UpgradeSucceeded).ok) 'no start'}
Case 'failed-upgrade-never-restarts' {$f=NewFixture;$f.state.processes=@(NewProcess);$p=Plan $f;Require ((Stop-FileBridgeLifecycle -Plan $p -Approved).ok) 'stop';$r=Restore-FileBridgeLifecycle -Plan $p;Require ($r.code -eq 'lifecycle_upgrade_not_successful') 'upgrade';Require (@($f.state.calls|Where-Object operation -eq 'start').Count -eq 0) 'no start'}
Case 'receipt-tamper-refused' {
    $f=NewFixture;$p=Plan $f;Require ((Stop-FileBridgeLifecycle -Plan $p -Approved).ok) 'stop';$receipt=Export-FileBridgeLifecycleReceipt -Plan $p
    Require ($receipt -notmatch 'bootstrap|synthetic-secret|CommandLine') 'no private argv';$bytes=[Text.Encoding]::UTF8.GetBytes($receipt);$sha=[Security.Cryptography.SHA256]::Create();try{$hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
    $r=Import-FileBridgeLifecycleReceipt -Receipt ($receipt+' ') -ExpectedSHA256 $hash -HermesHome 'C:\synthetic\home' -Profile default -Dependencies $f.dependencies;Require ($r.code -eq 'lifecycle_receipt_invalid') 'tamper'
    $r=Import-FileBridgeLifecycleReceipt -Receipt $receipt -ExpectedSHA256 $hash -HermesHome 'C:\synthetic\home' -Profile default -Dependencies $f.dependencies;Require $r.ok 'valid receipt';Require ((Restore-FileBridgeLifecycle -Plan $r -UpgradeSucceeded).ok) 'resume stopped'
}
Case 'planned-receipt-preserves-exact-running-instance' {
    $f=NewFixture;$f.state.processes=@(NewProcess);$p=Plan $f;$receipt=Export-FileBridgeLifecycleReceipt -Plan $p
    $loaded=Import-FileBridgeLifecycleReceipt -Receipt $receipt -ExpectedSHA256 (ReceiptHash $receipt) -HermesHome 'C:\synthetic\home' -Dependencies $f.dependencies
    Require $loaded.ok 'planned import';Require ((Stop-FileBridgeLifecycle -Plan $loaded -Approved).ok) 'continued stop';Require ($f.state.clock -ge 10) 'stable observation'
    Require ((Restore-FileBridgeLifecycle -Plan $loaded -UpgradeSucceeded).ok) 'restore original';Require ((Restore-FileBridgeLifecycle -Plan $loaded -UpgradeSucceeded).ok) 'idempotent restore'
    Require (@($f.state.calls|Where-Object operation -eq 'start').Count -eq 1) 'no double start'
}
Case 'planned-receipt-after-interrupted-stop-does-not-double-stop' {
    $f=NewFixture;$f.state.processes=@(NewProcess);$p=Plan $f;$receipt=Export-FileBridgeLifecycleReceipt -Plan $p;$f.state.processes=@()
    $loaded=Import-FileBridgeLifecycleReceipt -Receipt $receipt -ExpectedSHA256 (ReceiptHash $receipt) -HermesHome 'C:\synthetic\home' -Dependencies $f.dependencies
    Require $loaded.ok 'stopped receipt import';Require ((Stop-FileBridgeLifecycle -Plan $loaded -Approved).ok) 'idempotent stop';Require ($f.state.calls.Count -eq 0) 'no double stop command'
    Require ((Restore-FileBridgeLifecycle -Plan $loaded -UpgradeSucceeded).ok) 'restore intended original'
}
Case 'planned-receipt-does-not-adopt-replacement-instance' {
    $f=NewFixture;$f.state.processes=@(NewProcess);$p=Plan $f;$receipt=Export-FileBridgeLifecycleReceipt -Plan $p;$f.state.processes=@(NewProcess 'gateway' 32)
    $loaded=Import-FileBridgeLifecycleReceipt -Receipt $receipt -ExpectedSHA256 (ReceiptHash $receipt) -HermesHome 'C:\synthetic\home' -Dependencies $f.dependencies
    Require ($loaded.code -eq 'lifecycle_receipt_instance_changed') 'replacement blocked';Require ($f.state.calls.Count -eq 0) 'no command'
}
Case 'complete-originally-stopped-without-stop-command' {
    $f=NewFixture;$p=Plan $f;Require ((Restore-FileBridgeLifecycle -Plan $p -UpgradeSucceeded).ok) 'complete';Require ($f.state.calls.Count -eq 0) 'no command';Require ($f.state.clock -ge 10) 'stable verify'
}
Case 'launcher-changed-after-stop-no-restart' {
    $f=NewFixture;$f.state.processes=@(NewProcess);$p=Plan $f;Require ((Stop-FileBridgeLifecycle -Plan $p -Approved).ok) 'stop'
    $newProof=@{};foreach($key in $f.proof.Keys){$newProof[$key]=$f.proof[$key]};$newProof.launcher_sha256='c'*64
    $f.dependencies.Inspect={param($h,$l,$s) return $newProof}.GetNewClosure()
    $result=Restore-FileBridgeLifecycle -Plan $p -UpgradeSucceeded;Require ($result.code -eq 'lifecycle_launcher_changed') 'changed launcher';Require (@($f.state.calls|Where-Object operation -eq 'start').Count -eq 0) 'no command'
}
Case 'dashboard-and-serve-parameters-are-not-guessed' {
    foreach($bad in @(@('serve','--port','9119'),@('dashboard'),@('dashboard','--no-open','--host','0.0.0.0','--port','9119','--skip-build'),@('gateway','run','--replace'))) {
        $failed=$false;try {Get-CfLifecycleRestoreArgs $bad|Out-Null}catch{$failed=$_.Exception.Message -eq 'lifecycle_launch_shape_unsupported'};Require $failed 'unsupported shape rejected'
    }
}
Case 'native-argv-roundtrip-without-shell-execution' {
    Initialize-CfLifecycleNative
    $values=@('x.exe','C:\space path\python.exe','literal"quote','trailing\\','--profile','default')
    $line=($values|ForEach-Object{ConvertTo-CfLifecycleQuotedArg $_}) -join ' '
    $parsed=@([CfFileBridge.LifecycleArgvV1]::Parse($line));Require ($parsed.Count -eq $values.Count) 'argc';for($n=0;$n -lt $values.Count;$n++){Require ($parsed[$n] -ceq $values[$n]) 'exact argv'}
}
Case 'native-gateway-record-lock-and-incarnation' {
    $fixture=Join-Path ([IO.Path]::GetTempPath()) ('cf-lifecycle-metadata-'+[Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($fixture)|Out-Null;$handle=$null
    try {
        $created=[DateTime]::SpecifyKind([DateTime]'2026-09-30T00:00:00',[DateTimeKind]::Utc)
        $row=@{ProcessId=31;CreationDate=$created}
        $epoch=[Math]::Round(($created-[DateTime]::SpecifyKind([DateTime]'1970-01-01',[DateTimeKind]::Utc)).TotalSeconds*100)
        $record=@{pid=31;kind='hermes-gateway';start_time=$epoch;hermes_home=$fixture;argv=@('synthetic-no-content')}
        foreach($name in @('gateway.pid','gateway.lock')){[IO.File]::WriteAllText((Join-Path $fixture $name),($record|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))}
        Require (-not (Test-CfLifecycleGatewayRecord $row $fixture)) 'unlocked file is not authority'
        $handle=[IO.FileStream]::new((Join-Path $fixture 'gateway.lock'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete));$handle.Lock(1048576,1)
        Require (Test-CfLifecycleGatewayRecord $row $fixture) 'exact two records and active native lock'
        $row.CreationDate=$created.AddSeconds(1);Require (-not (Test-CfLifecycleGatewayRecord $row $fixture)) 'PID reuse rejected'
    } finally {
        if($handle){$handle.Unlock(1048576,1);$handle.Dispose()}
        # Only these two freshly created synthetic files; never a recursive cleanup.
        foreach($name in @('gateway.pid','gateway.lock')){[IO.File]::Delete((Join-Path $fixture $name))};[IO.Directory]::Delete($fixture)
    }
}
Case 'safe-errors-require-exact-known-code' {
    $f=NewFixture;$f.dependencies.Snapshot={param($h,$p) throw 'lifecycle_private_value_not_a_defined_code'}
    $p=Plan $f;Require ($p.code -ceq 'lifecycle_observation_failed') 'syntactically plausible private text is not a known code'
    Require (($p|ConvertTo-Json) -notmatch 'private_value') 'private message absent'
}
Case 'slow-first-observation-does-not-count-as-stopped-window' {
    $f=NewFixture;$state=$f.state
    $f.dependencies.Snapshot={param($h,$p) $state.clock+=12;return @{processes=@();tasks=@();unknown=@()}}.GetNewClosure()
    $p=Plan $f;$before=$state.clock;Require ((Stop-FileBridgeLifecycle -Plan $p -Approved).ok) 'stop'
    Require (($state.clock-$before) -ge 37) 'ten second window starts after first negative observation, with another observation'
}
Write-Output ('SETUP_LIFECYCLE_RESULT='+(@{ok=$true;cases=$script:cases;synthetic_observations=$true;real_hermes_executed=$false}|ConvertTo-Json -Compress))
