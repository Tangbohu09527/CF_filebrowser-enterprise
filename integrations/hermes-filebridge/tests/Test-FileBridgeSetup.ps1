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
        Restore={ $script:trace.Add('restore'); if($script:failure -eq 'restore'){throw 'fixture-private-secret'} }
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
$script:trace.Clear();$result=Invoke-CfSetupFlow -Dependencies (Dependencies 'complete' 'restore') -Approved
Assert (-not $result.ok -and $result.services_restored -ceq 'uncertain') 'failed restore cannot claim no service started'
foreach($code in @('CF_CONFIG_CONCURRENT_CHANGE','CF_UPGRADE_CHECKPOINT_PAYLOAD_NOT_COMPATIBLE','CF_UPGRADE_LEGACY_RESIDUE_CONFLICT')) {
    $exception=[InvalidOperationException]::new($code);$exception.Data['cf_target']='plugin/inbound_host.py';$exception.Data['cf_stage']='target_recheck';$exception.Data['cf_rename_completed']=$false
    $result=Get-CfSetupFailure ([pscustomobject]@{Exception=$exception}) 'preflight'
    Assert ($result.code -ceq $code -and $result.target -ceq 'plugin/inbound_host.py' -and $result.detail_stage -ceq 'target_recheck' -and $result.replacement_completed -eq $false) 'bounded concrete diagnostics'
}
$result=Get-CfSetupFailure ([pscustomobject]@{Exception=[Exception]::new('CF_CONFIG_FUTURE_PRIVATE_SENTINEL')}) 'preflight'
Assert ($result.code -ceq 'CF_SETUP_STEP_FAILED') 'unknown same-prefix errors stay redacted'
$result=Get-CfSetupFailure ([pscustomobject]@{Exception=[Exception]::new('CF_UPGRADE_PYTHON_STEP_FAILED:config_semantic_plan:content_toolset_disabled')}) 'preflight'
Assert ($result.code -ceq 'CF_UPGRADE_PYTHON_STEP_FAILED' -and $result.reason_code -ceq 'content_toolset_disabled') 'known permission conflict remains diagnostic'
$result=Get-CfSetupFailure ([pscustomobject]@{Exception=[Exception]::new('CF_UPGRADE_PYTHON_STEP_FAILED:config_semantic_plan:private_value')}) 'preflight'
Assert ($result.code -ceq 'CF_SETUP_STEP_FAILED' -and $result.reason_code -ceq 'none') 'unknown parser value redacted'
Write-Output 'FILEBRIDGE_SETUP_POLICY=PASS:18'

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
    $source='b'*40;$layout=Get-CfSetupLocation $fixture $source
    $profileKey=Get-CfSetupTextHash ([IO.Path]::Combine($fixture,'hermes').ToLowerInvariant())
    # Longest real member of the fixed 6f wheel archive (both cp311/cp314):
    # 91 characters, from lxml 6.1.3. Keep a 64-character LocalAppData prefix
    # budget; this is stricter than the default profile observed in the native
    # failure. The constraint comes from the installed file, not folder labels.
    $longestWheelMember='lxml/isoschematron/resources/xsl/iso-schematron-xslt1/iso_schematron_skeleton_for_xslt1.xsl'
    Assert ($longestWheelMember.Length -eq 91) 'fixed real wheel member evidence length'
    $runtimeMember='parser-runtime/Lib/site-packages/'+$longestWheelMember
    $projectedInstalledLength=64+($layout.Plan.Length-$fixture.Length)+1+$runtimeMember.Length
    Assert ($projectedInstalledLength -lt 260) 'default transaction keeps actual longest wheel file below legacy MAX_PATH with 64-char profile-root budget'
    Assert ($layout.Transactions -ceq (Join-Path $fixture 'CF-FileBridge/t')) 'new transaction layout avoids long-path wheel extraction'
    Assert ($layout.Key -ceq $profileKey -and $layout.Key.Length -eq 64) 'mutex and checkpoint retain full profile identity'
    Assert ([IO.Path]::GetFileName($layout.Account) -ceq $profileKey.Substring(0,32) -and [IO.Path]::GetFileName($layout.Plan) -ceq $source.Substring(0,12)) 'only directory labels shorten identity'
    foreach($path in @($layout.Storage,$layout.Transactions,$layout.Account,$layout.Plan)){[IO.Directory]::CreateDirectory($path,$acl)|Out-Null}
    $discovered=Get-CfSetupLocation $fixture $source
    Assert ($discovered.Plan -ceq $layout.Plan) 'strict 12-hex transaction discovered'
    $unknown=Join-Path $layout.Account ('c'*40);[IO.Directory]::CreateDirectory($unknown,$acl)|Out-Null
    $refused=$false;try {Get-CfSetupLocation $fixture $source|Out-Null}catch{$refused=$_.Exception.Message -ceq 'CF_SETUP_UNKNOWN_TRANSACTION_FILE'}
    Assert ($refused -and (Test-Path -LiteralPath $unknown)) 'unknown long-name transaction remains untouched and refuses discovery'
    $legacyData=Join-Path $fixture 'legacy-localdata';[IO.Directory]::CreateDirectory($legacyData,$acl)|Out-Null
    $legacyPlan=Join-Path $legacyData 'CF-FileBridge-upgrade-6f59267c/plan';[IO.Directory]::CreateDirectory($legacyPlan)|Out-Null
    $legacyLocation=Get-CfSetupLocation $legacyData $source
    Assert ($legacyLocation.Plan -ceq $legacyPlan) 'existing fixed 6f plan path is unchanged'
    Write-Output 'FILEBRIDGE_SETUP_LAYOUT=PASS:4;full_profile_identity_preserved=true;legacy_path_unchanged=true'
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
