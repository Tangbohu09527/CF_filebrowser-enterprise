# Orchestration policy tests. Native file transactions are exercised separately.
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot '../windows/Setup-FileBridge.ps1')
function Assert($Value,$Label) { if(-not $Value){throw ('TEST_FAILED: '+$Label)} }
$script:trace=[Collections.Generic.List[string]]::new()
function Dependencies($State,$Failure='') {
    $script:fixtureState=$State;$script:failure=$Failure
    return @{
        Check={ $script:trace.Add('check'); @{transaction_state=$script:fixtureState;safe_to_resume=$true} }
        Prepare={ $script:trace.Add('prepare'); if($script:failure -eq 'prepare'){throw 'fixture-private-secret'} }
        Save={ $script:trace.Add('save') }
        Stop={ $script:trace.Add('stop'); if($script:failure -eq 'stop'){throw 'fixture-private-secret'} }
        Apply={ $script:trace.Add('apply'); if($script:failure -eq 'apply'){throw 'fixture-private-secret'} }
        Verify={ $script:trace.Add('verify'); if($script:failure -eq 'verify'){throw 'fixture-private-secret'} }
        Restore={ $script:trace.Add('restore') }
    }
}
foreach($state in @('fresh','unprepared','prepared','partial','complete')) {
    $script:trace.Clear();$result=Invoke-CfSetupFlow -Dependencies (Dependencies $state) -Approved
    Assert $result.ok ($state+' succeeds')
    $expected=if($state -eq 'complete'){'check,verify,restore'}elseif($state -in @('fresh','unprepared')){'check,prepare,save,stop,apply,verify,restore'}else{'check,save,stop,apply,verify,restore'}
    Assert (($script:trace -join ',') -ceq $expected) ($state+' ordered transaction')
}
foreach($stage in @('prepare','stop','apply','verify')) {
    $script:trace.Clear();$result=Invoke-CfSetupFlow -Dependencies (Dependencies 'unprepared' $stage) -Approved
    Assert (-not $result.ok -and $result.stage -eq $stage) ($stage+' safe failure stage')
    Assert (-not $script:trace.Contains('restore')) ($stage+' cannot start mixed installation')
    Assert (-not ($result|ConvertTo-Json).Contains('fixture-private-secret')) 'private exception redacted'
}
$script:trace.Clear();$result=Invoke-CfSetupFlow -Dependencies (Dependencies 'partial')
Assert (-not $result.ok -and ($script:trace -join ',') -eq 'check') 'approval required before any mutation'
$script:trace.Clear();$result=Invoke-CfSetupFlow -Dependencies (Dependencies 'unknown') -Approved
Assert (-not $result.ok -and ($script:trace -join ',') -eq 'check') 'unknown state never adopted'
Write-Output 'FILEBRIDGE_SETUP_POLICY=PASS:11'

# Reuse the actual Start function's assignment ASTs instead of constructing an
# equivalent action table. This catches GetNewClosure dynamic-module resolution
# failures while keeping UI, process discovery and installation out of the test.
$setupFile=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../windows/Setup-FileBridge.ps1'))
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($setupFile,[ref]$tokens,[ref]$errors)
Assert ($errors.Count -eq 0) 'actual entry parses'
$startAst=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Start-CfFileBridgeSetup'},$true)
Assert ($null -ne $startAst) 'actual Start function exists'
$actual=@{}
foreach($name in @('checkAction','receiptState','actions')) {
    $assignments=@($startAst.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left -is [Management.Automation.Language.VariableExpressionAst] -and $n.Left.VariablePath.UserPath -ceq $name},$true))
    Assert ($assignments.Count -eq 1) ('one actual '+$name+' assignment')
    $actual[$name]=[scriptblock]::Create($assignments[0].Extent.Text)
}
$pending=@($startAst.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
    $n.Extent.Text.StartsWith('if($receiptState.kind -ceq ''pending'')')},$true))
Assert ($pending.Count -eq 1) 'actual pending-receipt import branch exists'
$actual.pending=[scriptblock]::Create($pending[0].Extent.Text)

function InvokeActualActions([string]$ReceiptPath,[string]$State,[bool]$Fresh,[bool]$RestoreFails=$false,[bool]$OriginalRunning=$false,[bool]$ApplyFails=$false) {
    # Fresh locals model a new setup invocation. Only the immutable receipt and
    # markers cross invocations; no lifecycle plan or in-memory phase is reused.
    $trace=[Collections.Generic.List[string]]::new()
    $model=@{state=$State;restore_fails=$RestoreFails;original_running=$OriginalRunning;apply_fails=$ApplyFails}
    $fresh=$Fresh;$parameters=@{}
    $receipt=$ReceiptPath;$location=@{Plan=(Join-Path $fixture 'plan');Home=$fixture;Profile='default'}
    $life=@{ok=$true;plan_id='synthetic-new-invocation'}
    function Invoke-CfFreshSetup([string]$Mode) {
        $trace.Add('fresh-'+$Mode)
        if($Mode -ceq 'Prepare'){$model.state='prepared'}
        if($Mode -ceq 'Apply'){$model.state='complete'}
        return @{state=$model.state}
    }
    $upgradeDriver={param([string]$Mode)
        $trace.Add('upgrade-'+$Mode)
        if($Mode -ceq 'Prepare'){$model.state='prepared'}
        if($Mode -ceq 'Resume'){if($model.apply_fails){throw 'fixture-private-secret'};$model.state='complete'}
        return (@{transaction_state=$model.state;safe_to_resume=$true}|ConvertTo-Json -Compress)
    }
    function Export-FileBridgeLifecycleReceipt($Plan) {
        $trace.Add('export-stub')
        return (@{schema='synthetic-lifecycle-test';original_running=$model.original_running}|ConvertTo-Json -Compress)
    }
    function Import-FileBridgeLifecycleReceipt($Receipt,$ExpectedSHA256,$HermesHome,$Profile) {
        $trace.Add('import-stub')
        Assert ((Get-CfSetupTextHash $Receipt) -ceq $ExpectedSHA256) 'actual envelope binds opaque receipt'
        return @{ok=$true;plan_id='synthetic-imported-invocation'}
    }
    function Stop-FileBridgeLifecycle($Plan,[switch]$Approved) {
        $trace.Add('stop-stub');Assert $Approved 'actual Stop action passes approval';return @{ok=$true}
    }
    function Restore-FileBridgeLifecycle($Plan,[switch]$UpgradeSucceeded) {
        $trace.Add('restore-stub');Assert $UpgradeSucceeded 'actual Restore action requires verified success'
        return @{ok=(-not $model.restore_fails)}
    }
    . $actual.checkAction
    $check=& $checkAction
    . $actual.receiptState
    . $actual.pending
    . $actual.actions
    $result=Invoke-CfSetupFlow -Dependencies $actions -Approved
    return @{result=$result;trace=($trace -join ',');receipt_kind=$receiptState.kind;state=$model.state}
}

$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$fixture=Join-Path $temp ('cf-setup-actions-test-'+[Guid]::NewGuid().ToString('N'))
try {
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner($sid);$acl.SetGroup($sid);$acl.SetAccessRuleProtection($true,$false)
    foreach($who in @($sid.Value,'S-1-5-18')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($who),
            [Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    [IO.Directory]::CreateDirectory($fixture,$acl)|Out-Null
    $receipt=Join-Path $fixture 'fresh.json'
    $first=InvokeActualActions $receipt 'fresh' $true
    Assert ($first.result.ok -and $first.state -ceq 'complete') 'real Start fresh action construction succeeds'
    Assert ($first.trace -ceq 'fresh-Check,fresh-Check,fresh-Prepare,export-stub,stop-stub,fresh-Apply,fresh-Check,restore-stub') 'fresh real action order and local function resolution'
    Assert ((Test-Path -LiteralPath ($receipt+'.done')) -and (Test-Path -LiteralPath ($receipt+'.restore-intent'))) 'actual Restore writes both immutable bound markers'
    Write-Output 'FILEBRIDGE_SETUP_ACTION_CASE=fresh-real-construction:PASS'

    $receipt=Join-Path $fixture 'upgrade.json'
    $first=InvokeActualActions $receipt 'partial' $false $false $true
    Assert ($first.result.ok -and $first.trace -ceq 'upgrade-Check,upgrade-Check,export-stub,stop-stub,upgrade-Resume,upgrade-Check,restore-stub') 'real partial actions resume and restore'
    Write-Output 'FILEBRIDGE_SETUP_ACTION_CASE=partial-real-construction:PASS'
    $receiptHash=Get-CfSetupHash $receipt;$doneHash=Get-CfSetupHash ($receipt+'.done')
    # The first receipt describes originally running components. This new
    # invocation models a user who stopped them after success; history must not
    # import the previous PID/instance or restore that previous running state.
    $again=InvokeActualActions $receipt 'complete' $false $false $false
    Assert ($again.result.ok -and $again.receipt_kind -ceq 'complete' -and $again.trace -ceq 'upgrade-Check,upgrade-Check,upgrade-Check') 'successful re-entry never imports or restores historical running state'
    Assert ((Get-CfSetupHash $receipt) -ceq $receiptHash -and (Get-CfSetupHash ($receipt+'.done')) -ceq $doneHash) 're-entry leaves receipt and completion marker byte exact'
    Write-Output 'FILEBRIDGE_SETUP_ACTION_CASE=completed-new-invocation-keeps-current-state:PASS'

    $failed=$false;try {Get-CfSetupReceiptState $receipt (Join-Path $fixture 'plan') 'partial'|Out-Null}catch{$failed=$_.Exception.Message -ceq 'CF_SETUP_LIFECYCLE_RECEIPT_CONFLICT'}
    Assert $failed 'completion marker cannot authorize partial files'
    $failed=$false;try {Get-CfSetupReceiptState $receipt (Join-Path $fixture 'other-plan') 'complete'|Out-Null}catch{$failed=$_.Exception.Message -ceq 'CF_SETUP_LIFECYCLE_RECEIPT_CONFLICT'}
    Assert $failed 'receipt cannot move to another plan'
    Write-Output 'FILEBRIDGE_SETUP_ACTION_CASE=receipt-plan-and-state-binding:PASS'

    $receipt=Join-Path $fixture 'pending.json'
    $interrupted=InvokeActualActions $receipt 'partial' $false $false $true $true
    Assert (-not $interrupted.result.ok -and $interrupted.result.stage -ceq 'apply' -and -not(Test-Path -LiteralPath ($receipt+'.restore-intent'))) 'apply failure persists receipt without attempting restore'
    Assert (-not($interrupted.result|ConvertTo-Json).Contains('fixture-private-secret')) 'actual constructed action failure remains redacted'
    $receiptHash=Get-CfSetupHash $receipt
    $resumed=InvokeActualActions $receipt 'partial' $false
    Assert ($resumed.result.ok -and $resumed.receipt_kind -ceq 'pending' -and $resumed.trace -ceq 'upgrade-Check,import-stub,upgrade-Check,stop-stub,upgrade-Resume,upgrade-Check,restore-stub') 'new invocation imports saved pending lifecycle before actual resume action'
    Assert ((Get-CfSetupHash $receipt) -ceq $receiptHash) 'pending re-entry never overwrites original running-state receipt'
    Write-Output 'FILEBRIDGE_SETUP_ACTION_CASE=pending-new-invocation-imports-once:PASS'

    $receipt=Join-Path $fixture 'uncertain.json'
    $first=InvokeActualActions $receipt 'partial' $false $true $true
    Assert (-not $first.result.ok -and $first.result.stage -ceq 'restore') 'failed restore leaves a fixed restore-stage failure'
    Assert ((Test-Path -LiteralPath ($receipt+'.restore-intent')) -and -not(Test-Path -LiteralPath ($receipt+'.done'))) 'uncertain restore has intent without completion'
    $failed=$false;try {InvokeActualActions $receipt 'complete' $false|Out-Null}catch{$failed=$_.Exception.Message -ceq 'CF_SETUP_RESTORE_OUTCOME_UNCERTAIN'}
    Assert $failed 'new invocation refuses to guess an uncertain restore outcome'
    Write-Output 'FILEBRIDGE_SETUP_ACTION_CASE=uncertain-restore-preserved:PASS'

    $receipt=Join-Path $fixture 'externally-complete.json'
    $external=InvokeActualActions $receipt 'complete' $false
    Assert ($external.result.ok -and $external.receipt_kind -ceq 'complete_external' -and $external.trace -ceq 'upgrade-Check,upgrade-Check,upgrade-Check') 'externally completed plan never changes lifecycle'
    Assert (-not(Test-Path -LiteralPath $receipt)) 'read-only external completion creates no receipt'
    Write-Output 'FILEBRIDGE_SETUP_ACTION_CASE=external-complete-no-restore:PASS'
    Write-Output 'FILEBRIDGE_SETUP_ACTUAL_ACTIONS=PASS:7;native_and_lifecycle_callbacks=explicit_stubs;receipts=real_private_files'
} finally {
    $resolved=[IO.Path]::GetFullPath($fixture)
    if(-not $resolved.StartsWith($temp+'\',[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -cnotmatch '^cf-setup-actions-test-[0-9a-f]{32}$'){throw 'TEST_FAILED: cleanup boundary'}
    if(Test-Path -LiteralPath $fixture){Remove-Item -LiteralPath $fixture -Recurse -Force}
}
