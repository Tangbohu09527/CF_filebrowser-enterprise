# One interactive entry; transaction internals remain in the existing drivers.
[CmdletBinding()]
param([switch]$Run,[string]$ReleaseDirectory='')
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
# Definition-only components must live in script scope: GetNewClosure creates a
# dynamic module and cannot resolve functions dot-sourced inside Start below.
. (Join-Path $PSScriptRoot 'ConfigFile.ps1')
. (Join-Path $PSScriptRoot 'Setup-Lifecycle.ps1')
. (Join-Path $PSScriptRoot 'Setup-Fresh.ps1')

function Get-CfSetupFailure($Failure,[string]$Stage) {
    $code='CF_SETUP_STEP_FAILED';$target='none';$renamed='unknown';$detail='none';$lifecycle='none';$reason='none'
    $known=@(
        'CF_CONFIG_BEFORE_CHANGED','CF_CONFIG_CANDIDATE_HASH_MISMATCH','CF_CONFIG_CANDIDATE_SECURITY_MISMATCH',
        'CF_CONFIG_CONCURRENT_CHANGE','CF_CONFIG_DIFFERENT_VOLUME','CF_CONFIG_FILE_TYPE_OR_SIZE','CF_CONFIG_FINAL_READBACK_FAILED',
        'CF_CONFIG_INVALID_INPUT','CF_CONFIG_JOURNAL_CONFLICT','CF_CONFIG_JOURNAL_INVALID','CF_CONFIG_LEGACY_RESIDUE_MISMATCH',
        'CF_CONFIG_LOCAL_ABSOLUTE_REQUIRED','CF_CONFIG_OPERATION_FAILED','CF_CONFIG_REPARSE_REFUSED',
        'CF_CONFIG_STAGED_READBACK_FAILED','CF_CONFIG_TARGET_EXISTS','CF_CONFIG_UNOWNED_CANDIDATE','CF_CONFIG_UNSAFE_LINK',
        'CF_FRESH_CHECKPOINT_CONFLICT','CF_FRESH_COMPLETE_CONTENT_BUNDLE_REQUIRED','CF_FRESH_CONFIG_CHANGED',
        'CF_FRESH_CONFIG_CHECK_FAILED','CF_FRESH_CONFIG_ENABLEMENT_CONFLICT','CF_FRESH_DIRECTORY_CHANGED',
        'CF_FRESH_HERMES_STILL_RUNNING','CF_FRESH_HERMES_STOP_CONFIRMATION_REQUIRED','CF_FRESH_INCOMPLETE_PLAN',
        'CF_FRESH_INVENTORY_REQUIRED','CF_FRESH_LOCAL_NTFS_REQUIRED','CF_FRESH_LOCAL_PATH_REQUIRED','CF_FRESH_OPERATION_FAILED',
        'CF_FRESH_PAYLOAD_CHANGED','CF_FRESH_PROCESS_STATE_UNAVAILABLE','CF_FRESH_SEPARATE_PLAN_REQUIRED',
        'CF_FRESH_UNKNOWN_JOURNAL_FILE','CF_FRESH_UNKNOWN_PLAN_FILE','CF_FRESH_UNKNOWN_PLUGIN_DIRECTORY','CF_FRESH_UNKNOWN_PLUGIN_FILE',
        'CF_UPGRADE_CANDIDATE_SEMANTIC_CONFLICT','CF_UPGRADE_CHECKPOINT_CONFLICT','CF_UPGRADE_CHECKPOINT_PAYLOAD_NOT_COMPATIBLE',
        'CF_UPGRADE_CHECKPOINT_RELEASE_NOT_COMPATIBLE','CF_UPGRADE_CHECKPOINT_SHAPE_INVALID','CF_UPGRADE_CONCURRENT_CONTENT_CONFLICT',
        'CF_UPGRADE_CONFIG_CHANGED_DURING_PREPARE','CF_UPGRADE_CONFIG_TOO_LARGE','CF_UPGRADE_CONFIGURATION_PLAN_FAILED',
        'CF_UPGRADE_CONSUMER_BUNDLE_REQUIRED','CF_UPGRADE_DEPENDENCIES_MISSING_NO_AUTO_INSTALL','CF_UPGRADE_FILE_DIGEST_CONFLICT',
        'CF_UPGRADE_HERMES_HOME_PYTHON_STILL_RUNNING','CF_UPGRADE_JOURNAL_WITHOUT_CHECKPOINT','CF_UPGRADE_LEGACY_RESIDUE_CONFLICT',
        'CF_UPGRADE_LOCAL_CONFIG_MODIFICATION_PRESERVED','CF_UPGRADE_LOCAL_PLUGIN_MODIFICATION_PRESERVED',
        'CF_UPGRADE_OFFLINE_RUNTIME_DEPENDENCY_MISMATCH','CF_UPGRADE_OPERATION_FAILED','CF_UPGRADE_PARTIAL_RUNTIME_PRESERVED_USE_NEW_PLAN_DIRECTORY',
        'CF_UPGRADE_PLANNER_PIP_UNSUPPORTED','CF_UPGRADE_PREVIOUS_INVENTORY_CONFLICT','CF_UPGRADE_PREVIOUS_PLUGIN_DIGEST_MISSING',
        'CF_UPGRADE_PRIVATE_ACL_REQUIRED_NO_REPAIR','CF_UPGRADE_PRIVATE_DIRECTORY_REQUIRED','CF_UPGRADE_PRIVATE_OWNER_REQUIRED',
        'CF_UPGRADE_PROFILE_NAME_INVALID','CF_UPGRADE_PROFILE_SELECTOR_INVALID','CF_UPGRADE_PYTHON_RESPONSE_INVALID_NO_PRIVATE_OUTPUT',
        'CF_UPGRADE_PYTHON_START_FAILED','CF_UPGRADE_PYTHON_STEP_FAILED_NO_PRIVATE_OUTPUT','CF_UPGRADE_PYTHON_TIMEOUT',
        'CF_UPGRADE_REPARSE_CACHE_REFUSED','CF_UPGRADE_REPARSE_REFUSED','CF_UPGRADE_RUNTIME_CHECKPOINT_INCOMPLETE',
        'CF_UPGRADE_SELECTED_HERMES_PYTHON_STILL_RUNNING','CF_UPGRADE_UNKNOWN_BACKUP_ENTRY_PRESERVED',
        'CF_UPGRADE_UNKNOWN_CHECKPOINT_ENTRY_PRESERVED','CF_UPGRADE_UNKNOWN_CONFIG_CANDIDATE_PRESERVED',
        'CF_UPGRADE_UNKNOWN_CONSUMER_FILE_PRESERVED','CF_UPGRADE_UNKNOWN_JOURNAL_ENTRY_PRESERVED','CF_UPGRADE_UNKNOWN_PLUGIN_ENTRY_PRESERVED',
        'CF_UPGRADE_UNSUPPORTED_PYTHON_ABI','CF_SETUP_UNKNOWN_TRANSACTION','CF_SETUP_POST_VERIFY_FAILED','CF_SETUP_LIFECYCLE_REFUSED')
    $cause=$Failure.Exception
    while($cause) {
        if($known -ccontains $cause.Message){$code=$cause.Message}
        if($cause.Message -cmatch '^CF_UPGRADE_PYTHON_STEP_FAILED:(config_semantic_plan|runtime_dependencies|runtime_extract_wheels|runtime_inventory):([a-z_]+)$') {
            $allowedReasons=@('plugin_version_conflict','existing_plugin_not_enabled','existing_inbound_not_enabled',
                'existing_host_settings_missing','existing_host_settings_incomplete','existing_profile_revision_invalid',
                'existing_worker_digest_invalid','consumer_allowlist_missing','platform_toolsets_invalid','api_toolsets_invalid',
                'known_plugin_toolsets_invalid','agent_configuration_invalid','disabled_toolsets_invalid','content_toolset_disabled',
                'yaml_alias_changes_unrelated_settings','candidate_roundtrip_failed','runtime_pin_invalid','dependency_inventory_invalid',
                'dependency_inventory_incomplete','runtime_modified_or_unknown','wheel_archive_shape','wheel_archive_member',
                'wheel_archive_size','checkpoint_conflict','prepared_candidate_conflict','configuration_plan_failed')
            if($allowedReasons -ccontains $Matches[2]){$code='CF_UPGRADE_PYTHON_STEP_FAILED';$detail=$Matches[1];$reason=$Matches[2]}
        }
        if($cause.Data.Contains('cf_lifecycle_code')){$lifecycle=Get-CfLifecycleError ([pscustomobject]@{Exception=[Exception]::new([string]$cause.Data['cf_lifecycle_code'])})}
        if($cause.Data.Contains('cf_target')) {
            $value=[string]$cause.Data['cf_target']
            if($value -in @('config.yaml','plugin/__init__.py','plugin/plugin.yaml','plugin/inbound.py','plugin/inbound_control.py','plugin/inbound_directory.py','plugin/inbound_host.py','plugin/inbound_content.py')){$target=$value}
        }
        if($cause.Data.Contains('cf_rename_completed') -and $cause.Data['cf_rename_completed'] -is [bool]){$renamed=$cause.Data['cf_rename_completed']}
        if($cause.Data.Contains('cf_stage')) {
            $value=[string]$cause.Data['cf_stage']
            if($value -in @('input_validate','source_validate','candidate_create','candidate_security','candidate_write','candidate_verify','target_recheck','rename','final_verify','journal_validate','journal_create','journal_recover')){$detail=$value}
        }
        $cause=$cause.InnerException
    }
    return @{ok=$false;stage=$Stage;detail_stage=$detail;reason_code=$reason;lifecycle_code=$lifecycle;code=$code;target=$target;replacement_completed=$renamed;recoverable='recheck_required';services_restored=$(if($Stage -ceq 'restore'){'uncertain'}else{$false})}
}
function Assert-CfSetupLifecycleResult($Result) {
    if($Result.ok -ne $true){
        $failure=[InvalidOperationException]::new('CF_SETUP_LIFECYCLE_REFUSED')
        $failure.Data['cf_lifecycle_code']=Get-CfLifecycleError ([pscustomobject]@{Exception=[Exception]::new([string]$Result.code)})
        throw $failure
    }
}

function Invoke-CfSetupFlow {
    param([hashtable]$Dependencies,[switch]$Approved)
    $stage='check'
    try {
        $check=& $Dependencies.Check
        if($check.transaction_state -notin @('fresh','unprepared','prepared','partial','complete')) {throw 'CF_SETUP_UNKNOWN_TRANSACTION'}
        if(-not $Approved){return @{ok=$false;stage='approval';code='CF_SETUP_APPROVAL_REQUIRED';recoverable=$true}}
        if($check.transaction_state -ne 'complete') {
            if($check.transaction_state -in @('fresh','unprepared')) {$stage='prepare'; & $Dependencies.Prepare | Out-Null}
            $stage='save'; & $Dependencies.Save | Out-Null
            $stage='stop'; & $Dependencies.Stop | Out-Null
            $stage='apply'; & $Dependencies.Apply | Out-Null
        }
        $stage='verify'; & $Dependencies.Verify | Out-Null
        $stage='restore'; & $Dependencies.Restore | Out-Null
        return @{ok=$true;stage='complete';code='CF_SETUP_COMPLETE';recoverable=$false}
    } catch {
        return Get-CfSetupFailure $_ $stage
    }
}

function Get-CfSetupHash([string]$Path) {return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Get-CfSetupTextHash([string]$Text) {
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant()}finally{$algorithm.Dispose()}
}
function Assert-CfSetupDirectory([string]$Path) {
    $node=Get-Item -LiteralPath $Path -Force
    if(-not $node.PSIsContainer -or ($node.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'CF_SETUP_DIRECTORY_REFUSED'}
    for($parent=$node.Parent;$null -ne $parent;$parent=$parent.Parent){if($parent.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'CF_SETUP_DIRECTORY_REFUSED'}}
    $acl=Get-Acl -LiteralPath $Path;$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if(-not $acl.AreAccessRulesProtected -or -not $acl.AreAccessRulesCanonical -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid){throw 'CF_SETUP_PRIVATE_DIRECTORY_REQUIRED'}
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if($rule.IdentityReference.Value -notin @($sid,'S-1-5-18') -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow){throw 'CF_SETUP_PRIVATE_DIRECTORY_REQUIRED'}
    }
}
function New-CfSetupDirectory([string]$Path) {
    if(Test-Path -LiteralPath $Path){Assert-CfSetupDirectory $Path;return}
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
    foreach($who in @($sid.Value,'S-1-5-18')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($who),[Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    # CreateDirectory is CREATE_NEW and never repairs an existing ACL.
    [CfInboundStageNative]::CreateDirectory($Path,$acl.GetSecurityDescriptorBinaryForm());Assert-CfSetupDirectory $Path
}
function Write-CfSetupNewFile([string]$Path,[string]$Text) {
    $file=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.Encoding]::UTF8.GetBytes($Text);$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}
function Read-CfSetupRecord([string]$Path,[string[]]$Keys) {
    Initialize-CfConfigNative
    Assert-CfSetupDirectory ([IO.Path]::GetDirectoryName($Path))
    return Read-CfConfigJournal $Path $Keys
}
function Get-CfSetupReceiptState([string]$Receipt,[string]$PlanPath,[string]$TransactionState) {
    $done=$Receipt+'.done';$intent=$Receipt+'.restore-intent'
    if(-not(Test-Path -LiteralPath $Receipt)){
        if((Test-Path -LiteralPath $done) -or (Test-Path -LiteralPath $intent)){throw 'CF_SETUP_LIFECYCLE_RECEIPT_CONFLICT'}
        return @{kind=$(if($TransactionState -ceq 'complete'){'complete_external'}else{'new'});envelope=$null;intent=$intent;done=$done}
    }
    $envelope=Read-CfSetupRecord $Receipt @('schema','plan_sha256','sha256','receipt')
    $planHash=Get-CfSetupTextHash $PlanPath.ToLowerInvariant()
    if($envelope.schema -cne 'cf-filebridge-setup-lifecycle/v1' -or $envelope.plan_sha256 -cne $planHash -or $envelope.sha256 -cne (Get-CfSetupTextHash $envelope.receipt)){throw 'CF_SETUP_LIFECYCLE_RECEIPT_CONFLICT'}
    $bound=Get-CfSetupHash $Receipt
    if(Test-Path -LiteralPath $done){
        $record=Read-CfSetupRecord $done @('schema','receipt_sha256')
        if($record.schema -cne 'cf-filebridge-restore-complete/v1' -or $record.receipt_sha256 -cne $bound -or $TransactionState -cne 'complete'){throw 'CF_SETUP_LIFECYCLE_RECEIPT_CONFLICT'}
        return @{kind='complete';envelope=$envelope;intent=$intent;done=$done}
    }
    if(Test-Path -LiteralPath $intent){throw 'CF_SETUP_RESTORE_OUTCOME_UNCERTAIN'}
    return @{kind='pending';envelope=$envelope;intent=$intent;done=$done}
}
function Get-CfSetupLocation([string]$LocalData,[string]$Source) {
    $homePath=Join-Path $LocalData 'hermes';$profile='default';$profileRoot=$homePath
    $selector=Join-Path $homePath 'active_profile'
    if(Test-Path -LiteralPath $selector) {
        $item=Get-Item -LiteralPath $selector -Force
        if($item.Length -gt 256 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'CF_SETUP_PROFILE_SELECTOR_REFUSED'}
        $profile=[IO.File]::ReadAllText($selector).Trim()
        if($profile -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'){throw 'CF_SETUP_PROFILE_SELECTOR_REFUSED'}
        if($profile -cne 'default'){$profileRoot=Join-Path (Join-Path $homePath 'profiles') $profile}
    }
    $key=Get-CfSetupTextHash $profileRoot.ToLowerInvariant()
    $storage=Join-Path $LocalData 'CF-FileBridge';$transactions=Join-Path $storage 'transactions';$account=Join-Path $transactions $key
    $legacy=Join-Path $LocalData 'CF-FileBridge-upgrade-6f59267c/plan'
    $plans=@()
    if(Test-Path -LiteralPath $legacy){$plans+=,$legacy}
    if(Test-Path -LiteralPath $account) {
        Assert-CfSetupDirectory $account
        foreach($entry in @(Get-ChildItem -LiteralPath $account -Force)) {
            if(-not $entry.PSIsContainer -or $entry.Name -notmatch '^[a-f0-9]{40}$' -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'CF_SETUP_UNKNOWN_TRANSACTION_FILE'}
            $plans+=,$entry.FullName
        }
    }
    if($plans.Count -gt 1){throw 'CF_SETUP_AMBIGUOUS_TRANSACTIONS'}
    $planPath=if($plans.Count){$plans[0]}else{Join-Path $account $Source}
    return @{Home=$homePath;Profile=$profile;ProfileRoot=$profileRoot;Storage=$storage;Transactions=$transactions;Account=$account;Plan=$planPath;Key=$key;
        Python=(Join-Path $homePath 'hermes-agent/venv/Scripts/python.exe');Launcher=(Join-Path $env:USERPROFILE '.local/bin/hermes.cmd')}
}

function Start-CfFileBridgeSetup([string]$Package) {
    if($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){throw 'CF_SETUP_NATIVE_PS51_REQUIRED'}
    Add-Type -AssemblyName System.Windows.Forms
    $manifest=[IO.File]::ReadAllText((Join-Path $Package 'release-manifest.json'))|ConvertFrom-Json
    if($manifest.schema -cne 'cf-filebridge-setup/v1' -or $manifest.source_commit -notmatch '^[a-f0-9]{40}$' -or $manifest.inventory_sha256 -notmatch '^[a-f0-9]{64}$'){throw 'CF_SETUP_RELEASE_MANIFEST_REFUSED'}
    foreach($property in $manifest.files.PSObject.Properties) {
        if($property.Name -match '(^/|\\|:|(^|/)\.\.(/|$))' -or (Get-CfSetupHash (Join-Path $Package $property.Name)) -cne $property.Value){throw 'CF_SETUP_RELEASE_MANIFEST_REFUSED'}
    }
    $bundle=Join-Path $Package 'inbound-bundle';$pin=$manifest.inventory_sha256
    $stage=Join-Path $PSScriptRoot 'Manage-InboundClient.ps1';$upgradeDriver=Join-Path $PSScriptRoot 'Upgrade-InboundClient.ps1'
    & $stage -Mode Inspect -SourceDirectory $bundle -ExpectedInventorySHA256 $pin | Out-Null
    $location=Get-CfSetupLocation $env:LOCALAPPDATA $manifest.source_commit
    if(-not(Test-Path -LiteralPath $location.Python) -or -not(Test-Path -LiteralPath (Join-Path $location.ProfileRoot 'config.yaml'))){throw 'CF_SETUP_EXISTING_HERMES_REQUIRED'}
    $mutex=[Threading.Mutex]::new($false,('Local\CF-FileBridge-Setup-'+$location.Key));$locked=$false
    try {
        try{$locked=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$locked=$true}
        if(-not $locked){throw 'CF_SETUP_OTHER_UPGRADE_ACTIVE'}
        $fresh=(Test-Path -LiteralPath (Join-Path $location.Plan 'fresh-checkpoint.json')) -or -not(Test-Path -LiteralPath (Join-Path $location.ProfileRoot 'plugins/cf-filebridge'))
        $parameters=@{BundleDirectory=$bundle;ExpectedInventorySHA256=$pin;HermesHome=$location.Home;PythonPath=$location.Python}
        if($fresh){$parameters.ProfileDirectory=$location.ProfileRoot;$parameters.PlanDirectory=$location.Plan}
        else{$parameters.Profile=$location.Profile;$parameters.UpgradeDirectory=$location.Plan}
        $checkAction={
            if($fresh){$r=Invoke-CfFreshSetup -Mode Check @parameters;return @{transaction_state=$r.state;safe_to_resume=$true}}
            return (& $upgradeDriver -Mode Check @parameters|ConvertFrom-Json)
        }
        $check=& $checkAction
        $life=Get-FileBridgeLifecyclePlan -HermesHome $location.Home -Profile $location.Profile -LauncherPath $location.Launcher
        Assert-CfSetupLifecycleResult $life
        $message='FileBridge '+$manifest.source_commit.Substring(0,8)+"`r`nDetected: "+$check.transaction_state+"`r`n`r`nVerify the fixed package, prepare backups and offline dependencies, stop only verified Hermes components if necessary, complete the transaction and verify it. Restore only components that were running. A failure leaves a mixed installation stopped.`r`n`r`nNo Gateway server, WeChat or startup settings will be changed. Continue?"
        if([Windows.Forms.MessageBox]::Show($message,'FileBridge Setup',[Windows.Forms.MessageBoxButtons]::YesNo,[Windows.Forms.MessageBoxIcon]::Question) -ne [Windows.Forms.DialogResult]::Yes){return}
        foreach($directory in @($location.Storage,$location.Transactions,$location.Account)){New-CfSetupDirectory $directory}
        # Receipts are separate from the engine's immutable old checkpoint.
        $receiptRoot=Join-Path $location.Storage 'lifecycle';New-CfSetupDirectory $receiptRoot
        $receipt=Join-Path $receiptRoot ($location.Key+'.json')
        $receiptState=Get-CfSetupReceiptState $receipt $location.Plan $check.transaction_state
        if($receiptState.kind -ceq 'pending'){
            $envelope=$receiptState.envelope
            $life=Import-FileBridgeLifecycleReceipt -Receipt $envelope.receipt -ExpectedSHA256 $envelope.sha256 -HermesHome $location.Home -Profile $location.Profile
            Assert-CfSetupLifecycleResult $life
        }
        $actions=@{
            Check=$checkAction
            Prepare={if($fresh){Invoke-CfFreshSetup -Mode Prepare @parameters}else{& $upgradeDriver -Mode Prepare @parameters|Out-Null}}
            Save={if(-not(Test-Path -LiteralPath $receipt)){
                $privateReceipt=Export-FileBridgeLifecycleReceipt -Plan $life
                Write-CfSetupNewFile $receipt (@{schema='cf-filebridge-setup-lifecycle/v1';plan_sha256=(Get-CfSetupTextHash $location.Plan.ToLowerInvariant());sha256=(Get-CfSetupTextHash $privateReceipt);receipt=$privateReceipt}|ConvertTo-Json -Compress)
            }}
            Stop={$s=Stop-FileBridgeLifecycle -Plan $life -Approved;Assert-CfSetupLifecycleResult $s}
            Apply={if($fresh){Invoke-CfFreshSetup -Mode Apply @parameters -HermesStopped}else{& $upgradeDriver -Mode Resume @parameters -HermesStopped|Out-Null}}
            Verify={
                $verified=& $checkAction
                if($verified.transaction_state -cne 'complete'){throw 'CF_SETUP_POST_VERIFY_FAILED'}
            }
            Restore={
                if($receiptState.kind -in @('complete','complete_external')){return}
                $bound=Get-CfSetupHash $receipt
                Write-CfSetupNewFile $receiptState.intent (@{schema='cf-filebridge-restore-intent/v1';receipt_sha256=$bound}|ConvertTo-Json -Compress)
                $s=Restore-FileBridgeLifecycle -Plan $life -UpgradeSucceeded
                Assert-CfSetupLifecycleResult $s
                Write-CfSetupNewFile $receiptState.done (@{schema='cf-filebridge-restore-complete/v1';receipt_sha256=$bound}|ConvertTo-Json -Compress)
            }
        }
        $result=Invoke-CfSetupFlow -Dependencies $actions -Approved
        $result.source_commit=$manifest.source_commit;$result.fresh_install=$fresh;$result.installed_disabled=$fresh
        Write-CfSetupNewFile (Join-Path $receiptRoot ('result-'+[Guid]::NewGuid().ToString('N')+'.json')) ($result|ConvertTo-Json -Depth 5)
        $summary=if($result.ok){if($fresh){'Installed with inbound features disabled. Gateway authorization/configuration is still required.'}else{'Upgrade verified. Original stopped/running state preserved.'}}else{'Stopped safely at '+$result.stage+'/'+$result.detail_stage+'; '+$result.code+'; '+$result.reason_code+'; '+$result.lifecycle_code+'; target='+$result.target+'; replaced='+$result.replacement_completed+'; recovery='+$result.recoverable+'. No mixed installation was started.'}
        [Windows.Forms.MessageBox]::Show($summary,'FileBridge Setup',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Information)|Out-Null
        if(-not $result.ok){throw 'CF_SETUP_TRANSACTION_STOPPED'}
    }finally{if($locked){$mutex.ReleaseMutex()};$mutex.Dispose()}
}

if($Run) {
    try {Start-CfFileBridgeSetup $ReleaseDirectory}
    catch {
        # UI deliberately omits raw PowerShell errors and configuration content.
        Add-Type -AssemblyName System.Windows.Forms
        $known=@('CF_SETUP_OTHER_UPGRADE_ACTIVE','CF_SETUP_UNKNOWN_TRANSACTION_FILE','CF_SETUP_AMBIGUOUS_TRANSACTIONS','CF_SETUP_EXISTING_HERMES_REQUIRED','CF_SETUP_PRIVATE_DIRECTORY_REQUIRED','CF_SETUP_PROFILE_SELECTOR_REFUSED','CF_SETUP_RELEASE_MANIFEST_REFUSED','CF_SETUP_TRANSACTION_STOPPED','CF_SETUP_RESTORE_OUTCOME_UNCERTAIN','CF_SETUP_LIFECYCLE_RECEIPT_CONFLICT','CF_SETUP_LIFECYCLE_REFUSED')
        $safe=if($known -ccontains $_.Exception.Message){$_.Exception.Message}else{'CF_SETUP_PREFLIGHT_REFUSED'}
        $failure=Get-CfSetupFailure $_ 'preflight'
        $detail=$safe+'; '+$failure.code+'; '+$failure.reason_code+'; target='+$failure.target+'; stage='+$failure.detail_stage+'; '+$failure.lifecycle_code+'; replaced='+$failure.replacement_completed+'; recovery='+$failure.recoverable
        [Windows.Forms.MessageBox]::Show($detail+"`r`nNo cleanup or further restart will be attempted. Preserve the recorded recovery state.",'FileBridge Setup',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Error)|Out-Null
        exit 1
    }
}
