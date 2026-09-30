# Native fresh-install regression. No live installation, runtime import or service.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PythonPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot '../windows/Setup-Fresh.ps1')
. (Join-Path $PSScriptRoot '../windows/Setup-FileBridge.ps1')
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$utf8=[Text.UTF8Encoding]::new($false)
$root=Join-Path ([IO.Path]::GetTempPath()) ('cf-fresh-test-'+[Guid]::NewGuid().ToString('N'))
function Require([bool]$Value,[string]$Label) { if (-not $Value) { throw ('TEST_FAILED:'+ $Label) } }
function PrivateDirectory([string]$Path) {
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
    foreach ($who in @($sid.Value,'S-1-5-18')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($who),[Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    [IO.Directory]::CreateDirectory($Path,$acl) | Out-Null
}
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
PrivateDirectory $root
$bundle=Join-Path $root 'bundle';PrivateDirectory $bundle;PrivateDirectory (Join-Path $bundle 'plugin')
$names=@('__init__.py','plugin.yaml','inbound.py','inbound_control.py','inbound_directory.py','inbound_host.py','inbound_content.py')
$files=[ordered]@{}
foreach ($name in @('filebridge-inbound.exe','requirements-inbound-content.txt','content-wheels.zip')+@($names|ForEach-Object {'plugin/'+$_})) {
    [IO.File]::WriteAllText((Join-Path $bundle $name),('synthetic fixture '+$name),$utf8);$files[$name]=Hash (Join-Path $bundle $name)
}
[IO.File]::WriteAllText((Join-Path $bundle 'inventory.json'),([ordered]@{schema='cf-inbound-bundle/v1';source_commit=('d'*40);files=$files}|ConvertTo-Json -Depth 4),$utf8)
$pin=Hash (Join-Path $bundle 'inventory.json')
$cases=0
function Fixture([string]$Name) {
    $homePath=Join-Path $root $Name;PrivateDirectory $homePath
    $profilePath=Join-Path $homePath 'profile';PrivateDirectory $profilePath
    [IO.File]::WriteAllText((Join-Path $profilePath 'config.yaml'),"model: synthetic-model`nplugins: {}`n",$utf8)
    return @{BundleDirectory=$bundle;ExpectedInventorySHA256=$pin;ProfileDirectory=$profilePath;HermesHome=$homePath;PythonPath=$PythonPath;PlanDirectory=(Join-Path $homePath 'plan')}
}
$argsMap=Fixture 'normal';$config=Join-Path $argsMap.ProfileDirectory 'config.yaml';$oldHash=Hash $config
$oldAcl=Get-CfConfigSddl $config
$result=Invoke-CfFreshSetup @argsMap -Mode Check
Require ($result.state -ceq 'fresh' -and -not(Test-Path -LiteralPath $argsMap.PlanDirectory)) 'check read only'
$result=Invoke-CfFreshSetup @argsMap -Mode Prepare
Require ($result.state -ceq 'prepared' -and -not(Test-Path -LiteralPath (Join-Path $argsMap.ProfileDirectory 'plugins/cf-filebridge'))) 'prepare does not publish'
$denied=$false;try { Invoke-CfFreshSetup @argsMap -Mode Apply | Out-Null } catch {$denied=$true}
Require $denied 'apply requires stopped confirmation'
$result=Invoke-CfFreshSetup @argsMap -Mode Apply -HermesStopped
Require ($result.state -ceq 'complete' -and $result.installed_disabled -and $result.authorization_required) 'installed disabled boundary'
Require ((Hash $config) -ceq $oldHash -and (Get-CfConfigSddl $config) -ceq $oldAcl) 'configuration exact unchanged'
$result=Invoke-CfFreshSetup @argsMap -Mode Apply -HermesStopped
Require ($result.state -ceq 'complete') 'idempotent apply'
$cases++;Write-Output 'SETUP_FRESH_CASE=prepare-apply-repeat:PASS'

# Inject interruption only AFTER a real NTFS publish returns. No filesystem,
# descriptor, journal or ConfigFile operation is mocked. Resume must recognize
# each prefix from the on-disk directory and candidate identity receipts.
$nativeReplace=${function:Set-CfConfigBytesExact}
foreach($cut in 1..7) {
    $argsMap=Fixture ('boundary-'+$cut);$config=Join-Path $argsMap.ProfileDirectory 'config.yaml';$oldHash=Hash $config;$oldAcl=Get-CfConfigSddl $config
    $script:publishCount=0;$script:interruptAt=$cut
    function Set-CfConfigBytesExact {
        param($Destination,[byte[]]$Bytes,[AllowEmptyString()][string]$BeforeSha256,$AfterSha256,$OriginalSddl,$TransactionDirectory,$TargetName,[switch]$AllowCreate)
        $result=& $nativeReplace @PSBoundParameters
        $script:publishCount++
        if($script:publishCount -eq $script:interruptAt){throw 'SYNTHETIC_BOUNDARY_INTERRUPTION'}
        return $result
    }
    $denied=$false
    try {Invoke-CfFreshSetup @argsMap -Mode Apply -HermesStopped | Out-Null}catch{$denied=$true}
    finally {Set-Item -LiteralPath Function:Set-CfConfigBytesExact -Value $nativeReplace}
    Require ($denied -and $script:publishCount -eq $cut) 'actual publish boundary reached'
    $published=@(Get-ChildItem -LiteralPath (Join-Path $argsMap.ProfileDirectory 'plugins/cf-filebridge') -File -Force)
    Require ($published.Count -eq $cut) 'exact prefix published'
    $beforeTimes=@{};foreach($file in $published){$beforeTimes[$file.Name]=$file.LastWriteTimeUtc}
    $checked=Invoke-CfFreshSetup @argsMap -Mode Check
    Require ($checked.completed_files -eq $cut -and $checked.state -ceq $(if($cut -eq 7){'complete'}else{'partial'})) 'readonly partial state'
    $result=Invoke-CfFreshSetup @argsMap -Mode Apply -HermesStopped
    Require ($result.state -ceq 'complete') 'boundary resumes'
    foreach($file in $published){Require ((Get-Item -LiteralPath $file.FullName).LastWriteTimeUtc -eq $beforeTimes[$file.Name]) 'already published file not rewritten'}
    Require ((Hash $config) -ceq $oldHash -and (Get-CfConfigSddl $config) -ceq $oldAcl) 'boundary configuration untouched'
    $cases++;Write-Output ('SETUP_FRESH_CASE=publish-boundary-'+$cut+':PASS')
}
foreach($mode in @('existing-plugin','late-plugin','config-change','unknown-plan','unknown-journal','published-change','historical-enabled','historical-settings')) {
    $argsMap=Fixture $mode;$config=Join-Path $argsMap.ProfileDirectory 'config.yaml'
    $pluginParent=Join-Path $argsMap.ProfileDirectory 'plugins';$plugin=Join-Path $pluginParent 'cf-filebridge'
    if($mode -eq 'existing-plugin'){PrivateDirectory $pluginParent;PrivateDirectory $plugin;[IO.File]::WriteAllText((Join-Path $plugin 'unknown.txt'),'preserve',$utf8)}
    elseif($mode -eq 'historical-enabled'){[IO.File]::WriteAllText($config,"plugins:`n  enabled: [cf-filebridge]`n",$utf8)}
    elseif($mode -eq 'historical-settings'){[IO.File]::WriteAllText($config,"plugins:`n  entries:`n    cf-filebridge:`n      settings: {inbound_enabled: true}`n",$utf8)}
    else {
        Invoke-CfFreshSetup @argsMap -Mode Prepare | Out-Null
        if($mode -eq 'late-plugin'){PrivateDirectory $pluginParent;PrivateDirectory $plugin;[IO.File]::WriteAllText((Join-Path $plugin 'unknown.txt'),'preserve',$utf8)}
        if($mode -eq 'config-change'){[IO.File]::WriteAllText($config,"model: concurrent-model`nplugins: {}`n",$utf8)}
        if($mode -eq 'unknown-plan'){[IO.File]::WriteAllText((Join-Path $argsMap.PlanDirectory 'operator-note.txt'),'preserve',$utf8)}
        if($mode -eq 'unknown-journal'){[IO.File]::WriteAllText((Join-Path $argsMap.PlanDirectory 'candidate-journal/unknown.json'),'preserve',$utf8)}
        if($mode -eq 'published-change'){
            Invoke-CfFreshSetup @argsMap -Mode Apply -HermesStopped | Out-Null
            [IO.File]::WriteAllText((Join-Path $plugin 'inbound.py'),'operator changed',$utf8)
        }
    }
    $beforeHash=Hash $config;$beforeAcl=Get-CfConfigSddl $config
    $denied=$false;try{Invoke-CfFreshSetup @argsMap -Mode Apply -HermesStopped | Out-Null}catch{$denied=$true;Require ($_.Exception.Message -cmatch '^CF_(FRESH|CONFIG)_[A-Z_]+$') 'safe refusal code'}
    Require $denied ($mode+': must refuse')
    Require ((Hash $config) -ceq $beforeHash -and (Get-CfConfigSddl $config) -ceq $beforeAcl) ($mode+': config unchanged')
    if($mode -in @('existing-plugin','late-plugin')){Require ([IO.File]::ReadAllText((Join-Path $plugin 'unknown.txt')) -ceq 'preserve') 'unknown file kept'}
    if($mode -eq 'published-change'){Require ([IO.File]::ReadAllText((Join-Path $plugin 'inbound.py')) -ceq 'operator changed') 'modified source kept'}
    $cases++;Write-Output ('SETUP_FRESH_CASE='+$mode+':PASS')
}
foreach($flowMode in @('normal','partial')) {
    $argsMap=Fixture ('flow-'+$flowMode);$config=Join-Path $argsMap.ProfileDirectory 'config.yaml';$beforeHash=Hash $config;$beforeAcl=Get-CfConfigSddl $config
    $calls=[Collections.Generic.List[string]]::new()
    $actions=@{
        Check={$calls.Add('check');$r=Invoke-CfFreshSetup @argsMap -Mode Check;return @{transaction_state=$r.state}}.GetNewClosure()
        Prepare={$calls.Add('prepare');Invoke-CfFreshSetup @argsMap -Mode Prepare}.GetNewClosure()
        Save={$calls.Add('save');return @{synthetic_stopped_lifecycle=$true}}.GetNewClosure()
        Stop={$calls.Add('stop');return @{synthetic_stopped_lifecycle=$true}}.GetNewClosure()
        Apply={$calls.Add('apply');Invoke-CfFreshSetup @argsMap -Mode Apply -HermesStopped}.GetNewClosure()
        Verify={$calls.Add('verify');$r=Invoke-CfFreshSetup @argsMap -Mode Check;if($r.state -cne 'complete'){throw 'CF_SETUP_POST_VERIFY_FAILED'}}.GetNewClosure()
        Restore={$calls.Add('restore');return @{synthetic_stopped_lifecycle=$true}}.GetNewClosure()
    }
    if($flowMode -eq 'partial'){
        $script:publishCount=0
        function Set-CfConfigBytesExact {
            param($Destination,[byte[]]$Bytes,[AllowEmptyString()][string]$BeforeSha256,$AfterSha256,$OriginalSddl,$TransactionDirectory,$TargetName,[switch]$AllowCreate)
            $result=& $nativeReplace @PSBoundParameters;$script:publishCount++
            if($script:publishCount -eq 3){throw 'SYNTHETIC_BOUNDARY_INTERRUPTION'};return $result
        }
        try{$failed=Invoke-CfSetupFlow -Dependencies $actions -Approved}
        finally{Set-Item -LiteralPath Function:Set-CfConfigBytesExact -Value $nativeReplace}
        Require (-not $failed.ok -and $failed.stage -ceq 'apply') 'real Flow retains publish failure'
        Require (($calls -join ',') -ceq 'check,prepare,save,stop,apply') 'failed Flow never restores'
        Require (@(Get-ChildItem -LiteralPath (Join-Path $argsMap.ProfileDirectory 'plugins/cf-filebridge') -File).Count -eq 3) 'real Flow published prefix'
        $calls.Clear()
    }
    $result=Invoke-CfSetupFlow -Dependencies $actions -Approved
    Require $result.ok ('real Flow '+$flowMode+' complete')
    $expected=if($flowMode -eq 'normal'){'check,prepare,save,stop,apply,verify,restore'}else{'check,save,stop,apply,verify,restore'}
    Require (($calls -join ',') -ceq $expected) 'real Flow lifecycle order'
    foreach($name in $names){Require ((Hash (Join-Path $argsMap.ProfileDirectory ('plugins/cf-filebridge/'+$name))) -ceq $files['plugin/'+$name]) 'real Flow actual payload'}
    Require ((Hash $config) -ceq $beforeHash -and (Get-CfConfigSddl $config) -ceq $beforeAcl) 'real Flow keeps configuration'
    $cases++;Write-Output ('SETUP_FRESH_CASE=real-flow-'+$flowMode+':PASS')
}
Write-Output ('SETUP_FRESH_CASES_PASSED='+$cases)
Write-Output 'SETUP_FRESH_LIFECYCLE=synthetic-stopped;FILESYSTEM=real-NTFS;HERMES_EXECUTED=false'
