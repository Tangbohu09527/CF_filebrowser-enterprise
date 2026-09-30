# Offline fresh installation into an existing Hermes profile. Configuration is read
# only; this helper never installs Hermes, enables a plugin, starts or stops a process.
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'ConfigFile.ps1')

function Invoke-CfFreshSetup {
    [CmdletBinding()]
    param(
        [ValidateSet('Check','Prepare','Apply')][string]$Mode='Check',
        [Parameter(Mandatory=$true)][string]$BundleDirectory,
        [Parameter(Mandatory=$true)][string]$ExpectedInventorySHA256,
        [Parameter(Mandatory=$true)][string]$ProfileDirectory,
        [Parameter(Mandatory=$true)][string]$HermesHome,
        [Parameter(Mandatory=$true)][string]$PythonPath,
        [Parameter(Mandatory=$true)][string]$PlanDirectory,
        [switch]$HermesStopped
    )
    $ErrorActionPreference='Stop'
    $phase='preflight';$state='fresh';$completed=0;$relativeTarget='none'
    $held=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $configStream=$null
    $names=@('__init__.py','plugin.yaml','inbound.py','inbound_control.py','inbound_directory.py','inbound_host.py','inbound_content.py')
    $utf8=[Text.UTF8Encoding]::new($false)
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $stageDriver=Join-Path $PSScriptRoot 'Manage-InboundClient.ps1'
    function Fresh-Path([string]$Path) {
        if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.Substring(2).Contains(':') -or $Path -match '[\\/](\.|\.\.)([\\/]|$)' -or $Path -match '[ .]([\\/]|$)') { throw 'CF_FRESH_LOCAL_PATH_REQUIRED' }
        $value=[IO.Path]::GetFullPath($Path).TrimEnd('\','/')
        if ($value.Length -lt 4) { throw 'CF_FRESH_LOCAL_PATH_REQUIRED' }
        $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($value))
        if($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -cne 'NTFS'){throw 'CF_FRESH_LOCAL_NTFS_REQUIRED'}
        return $value
    }
    function Fresh-Hold([string]$Path) {
        if ($held.ContainsKey($Path)) { [CfInboundStageNative]::CheckDirectory($held[$Path]);return }
        $parent=[IO.Directory]::GetParent($Path);if ($parent) { Fresh-Hold $parent.FullName }
        $held.Add($Path,[CfInboundStageNative]::LockDirectory($Path))
    }
    function Fresh-Security([bool]$Directory) {
        $acl=if($Directory){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
        $acl.SetOwner($sid);$acl.SetGroup($sid);$acl.SetAccessRuleProtection($true,$false)
        $inherit=if($Directory){[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit}else{[Security.AccessControl.InheritanceFlags]::None}
        foreach($who in @($sid.Value,'S-1-5-18')) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($who),[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
        };return $acl
    }
    function Fresh-NewDirectory([string]$Path) {
        Fresh-Hold ([IO.Path]::GetDirectoryName($Path))
        [CfInboundStageNative]::CreateDirectory($Path,(Fresh-Security $true).GetSecurityDescriptorBinaryForm())
        Fresh-Hold $Path;Assert-CfConfigJournalDirectory $Path
    }
    function Fresh-ReadPinned([string]$Path,[string]$Expected,[long]$Limit) {
        $handle=[CfInboundStageNative]::OpenFileRead($Path);$stream=[IO.FileStream]::new($handle,[IO.FileAccess]::Read)
        try {
            if($stream.Length -gt $Limit){throw 'CF_FRESH_PAYLOAD_CHANGED'}
            $data=New-Object byte[] $stream.Length;$offset=0
            while($offset -lt $data.Length){$read=$stream.Read($data,$offset,$data.Length-$offset);if($read -eq 0){throw 'CF_FRESH_PAYLOAD_CHANGED'};$offset+=$read}
            $hash=[Security.Cryptography.SHA256]::Create()
            try{$actual=([BitConverter]::ToString($hash.ComputeHash($data))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
            if($actual -cne $Expected){throw 'CF_FRESH_PAYLOAD_CHANGED'}
            return ,$data
        } finally {$stream.Dispose()}
    }
    function Fresh-AssertStopped {
        # No command-line or environment inspection.
        foreach($process in Get-Process -Name python,pythonw,hermes -ErrorAction SilentlyContinue) {
            try {$executable=$process.Path}catch{throw 'CF_FRESH_PROCESS_STATE_UNAVAILABLE'}
            if (-not $executable) {throw 'CF_FRESH_PROCESS_STATE_UNAVAILABLE'}
            if ($executable.Equals($PythonPath,[StringComparison]::OrdinalIgnoreCase) -or $executable.StartsWith($HermesHome+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'CF_FRESH_HERMES_STILL_RUNNING'}
        }
    }
    function Fresh-Disabled([byte[]]$ConfigBytes) {
        # Mature YAML parsing only. No Hermes import, no profile discovery and no
        # credentials in arguments/stdout/stderr. The caller selects the interpreter.
        $code=@'
import sys
from ruamel.yaml import YAML
try:
    d=YAML(typ="safe").load(sys.stdin.buffer.read())
    assert isinstance(d,dict)
    p=d.get("plugins",{})
    assert isinstance(p,dict)
    enabled=p.get("enabled",[])
    assert isinstance(enabled,list) and "cf-filebridge" not in enabled
    entries=p.get("entries",{})
    assert isinstance(entries,dict)
    entry=entries.get("cf-filebridge",{})
    assert isinstance(entry,dict)
    settings=entry.get("settings",{})
    assert isinstance(settings,dict) and entry.get("enabled") is not True
    assert not any(v is True for k,v in settings.items() if isinstance(k,str) and (k=="enabled" or k.endswith("_enabled")))
    print("true")
except Exception:
    print("false")
'@
        $encoded=[Convert]::ToBase64String($utf8.GetBytes($code))
        $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$PythonPath
        $start.Arguments='-I -X utf8 -B -c "import base64;exec(base64.b64decode('''+$encoded+'''))"'
        $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
        $start.EnvironmentVariables.Clear()
        foreach($key in @('SystemRoot','WINDIR')) {if([Environment]::GetEnvironmentVariable($key)){$start.EnvironmentVariables[$key]=[Environment]::GetEnvironmentVariable($key)}}
        $start.EnvironmentVariables['PATH']=(Join-Path $env:SystemRoot 'System32')
        $process=[Diagnostics.Process]::Start($start)
        try {
            $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
            $process.StandardInput.BaseStream.Write($ConfigBytes,0,$ConfigBytes.Length);$process.StandardInput.Close()
            if(-not $process.WaitForExit(15000)){$process.Kill();$process.WaitForExit();throw 'CF_FRESH_CONFIG_CHECK_FAILED'}
            if($process.ExitCode -ne 0 -or $stdout.Result.Trim() -cne 'true' -or $stderr.Result.Length -ne 0){throw 'CF_FRESH_CONFIG_ENABLEMENT_CONFLICT'}
        } finally {$process.Dispose()}
    }
    function Fresh-DirectoryReceipt([string]$Path,[string]$Receipt,[bool]$Create) {
        if (Test-Path -LiteralPath $Receipt) {
            $record=Read-CfConfigJournal $Receipt @('path','identity','security')
            Fresh-Hold $Path;Assert-CfConfigJournalDirectory $Path
            if($record.path -cne $Path -or $record.identity -cne [CfFileBridge.ConfigNativeV1]::IdentityHandle($held[$Path]) -or $record.security -cne (Get-CfConfigSddl $Path)){throw 'CF_FRESH_DIRECTORY_CHANGED'}
        } elseif(Test-Path -LiteralPath $Path) {throw 'CF_FRESH_UNKNOWN_PLUGIN_DIRECTORY'}
        elseif($Create) {
            Fresh-NewDirectory $Path
            Write-CfConfigJournal $Receipt ([ordered]@{path=$Path;identity=[CfFileBridge.ConfigNativeV1]::IdentityHandle($held[$Path]);security=(Get-CfConfigSddl $Path)})
        }
    }
    try {
        if($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){throw 'CF_FRESH_WINDOWS_POWERSHELL_REQUIRED'}
        if($ExpectedInventorySHA256 -cnotmatch '^[0-9a-f]{64}$'){throw 'CF_FRESH_INVENTORY_REQUIRED'}
        if($Mode -eq 'Apply' -and (-not $PSBoundParameters.ContainsKey('HermesStopped') -or -not $PSBoundParameters['HermesStopped'])){throw 'CF_FRESH_HERMES_STOP_CONFIRMATION_REQUIRED'}
        $BundleDirectory=Fresh-Path $BundleDirectory;$ProfileDirectory=Fresh-Path $ProfileDirectory
        $HermesHome=Fresh-Path $HermesHome;$PythonPath=Fresh-Path $PythonPath;$PlanDirectory=Fresh-Path $PlanDirectory
        if($PlanDirectory.StartsWith($ProfileDirectory+'\',[StringComparison]::OrdinalIgnoreCase) -or $PlanDirectory.Equals($ProfileDirectory,[StringComparison]::OrdinalIgnoreCase)){throw 'CF_FRESH_SEPARATE_PLAN_REQUIRED'}
        $inspection=& $stageDriver -Mode Inspect -SourceDirectory $BundleDirectory -ExpectedInventorySHA256 $ExpectedInventorySHA256 | ConvertFrom-Json
        if($inspection.payload_count -ne 10){throw 'CF_FRESH_COMPLETE_CONTENT_BUNDLE_REQUIRED'}
        Fresh-Hold $ProfileDirectory;Fresh-Hold $HermesHome
        Initialize-CfConfigNative
        $config=Join-Path $ProfileDirectory 'config.yaml';Assert-CfConfigPath $config
        $handle=[CfInboundStageNative]::OpenFileRead($config);$configStream=[IO.FileStream]::new($handle,[IO.FileAccess]::Read)
        $bytes=New-Object byte[] $configStream.Length;$offset=0
        while($offset -lt $bytes.Length){$read=$configStream.Read($bytes,$offset,$bytes.Length-$offset);if($read -eq 0){throw 'CF_FRESH_CONFIG_CHECK_FAILED'};$offset+=$read}
        $configHash=Get-CfConfigHash $config;$configSecurity=Get-CfConfigSddl $config;$configIdentity=[CfFileBridge.ConfigNativeV1]::IdentityHandle($handle)
        Fresh-Disabled $bytes
        $pluginParent=Join-Path $ProfileDirectory 'plugins';$plugin=Join-Path $pluginParent 'cf-filebridge'
        $checkpoint=Join-Path $PlanDirectory 'fresh-checkpoint.json';$stageDirectory=Join-Path $PlanDirectory 'stage';$journalDirectory=Join-Path $PlanDirectory 'candidate-journal'
        $fileSecurity=(Fresh-Security $false).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group)
        $fields=@('version','profile','home','inventory','source_commit','config_hash','config_security','config_identity','file_security','plugins_existed')
        if(Test-Path -LiteralPath $PlanDirectory) {
            Fresh-Hold $PlanDirectory;Assert-CfConfigJournalDirectory $PlanDirectory
            $record=Read-CfConfigJournal $checkpoint $fields
            if($record.version -ne 1 -or $record.profile -cne $ProfileDirectory -or $record.home -cne $HermesHome -or $record.inventory -cne $ExpectedInventorySHA256 -or $record.source_commit -cne $inspection.source_commit -or
                $record.config_hash -cne $configHash -or $record.config_security -cne $configSecurity -or $record.config_identity -cne $configIdentity -or $record.file_security -cne $fileSecurity -or $record.plugins_existed -isnot [bool]){throw 'CF_FRESH_CHECKPOINT_CONFLICT'}
        } else {
            if(Test-Path -LiteralPath $plugin){throw 'CF_FRESH_UNKNOWN_PLUGIN_DIRECTORY'}
            if($Mode -eq 'Check'){return [pscustomobject]@{state='fresh';installed_disabled=$false;authorization_required=$true;business_ready=$false;completed_files=0}}
            $phase='prepare'
            $parent=[IO.Path]::GetDirectoryName($PlanDirectory);Fresh-Hold $parent;Assert-CfConfigJournalDirectory $parent
            Fresh-NewDirectory $PlanDirectory
            $record=[pscustomobject][ordered]@{version=1;profile=$ProfileDirectory;home=$HermesHome;inventory=$ExpectedInventorySHA256;source_commit=$inspection.source_commit;config_hash=$configHash;config_security=$configSecurity;config_identity=$configIdentity;file_security=$fileSecurity;plugins_existed=[bool](Test-Path -LiteralPath $pluginParent)}
            Write-CfConfigJournal $checkpoint $record
        }
        $allowedPlan=@('fresh-checkpoint.json','stage','candidate-journal','plugins-directory.json','plugin-directory.json')
        foreach($node in Get-ChildItem -LiteralPath $PlanDirectory -Force){if($allowedPlan -cnotcontains $node.Name){throw 'CF_FRESH_UNKNOWN_PLAN_FILE'}}
        $stageMode=if($Mode -eq 'Check'){'Check'}elseif(Test-Path -LiteralPath $stageDirectory){'Resume'}else{'Stage'}
        $null=& $stageDriver -Mode $stageMode -SourceDirectory $BundleDirectory -StageDirectory $stageDirectory -ExpectedInventorySHA256 $ExpectedInventorySHA256
        if(-not(Test-Path -LiteralPath $journalDirectory)) {if($Mode -eq 'Check'){throw 'CF_FRESH_INCOMPLETE_PLAN'};Fresh-NewDirectory $journalDirectory}
        Fresh-Hold $journalDirectory;Assert-CfConfigJournalDirectory $journalDirectory
        $state='prepared'
        if($Mode -eq 'Apply'){Fresh-AssertStopped}
        if($record.plugins_existed){
            if(Test-Path -LiteralPath (Join-Path $PlanDirectory 'plugins-directory.json')){throw 'CF_FRESH_UNKNOWN_PLAN_FILE'}
            Fresh-Hold $pluginParent
        }
        else{Fresh-DirectoryReceipt $pluginParent (Join-Path $PlanDirectory 'plugins-directory.json') ($Mode -eq 'Apply')}
        Fresh-DirectoryReceipt $plugin (Join-Path $PlanDirectory 'plugin-directory.json') ($Mode -eq 'Apply')
        $inventory=ConvertFrom-Json -InputObject ($utf8.GetString((Fresh-ReadPinned (Join-Path $stageDirectory 'inventory.json') $ExpectedInventorySHA256 16384)))
        $knownJournal=@();$knownCandidates=@()
        foreach($name in $names){
            $relative='plugin/'+$name;$target=Join-Path $plugin $name
            $hash=$inventory.files.PSObject.Properties[$relative].Value
            $journal=Assert-CfConfigTransactionJournal -TransactionDirectory $journalDirectory -TargetName $relative -Destination $target -BeforeSha256 '' -AfterSha256 $hash -OriginalSddl $fileSecurity -AllowCreate
            $knownJournal+=@($journal.journal_names)
            if($journal.owned_candidate){$knownCandidates+=@($journal.candidate_name)}
            if(Test-Path -LiteralPath $target){if(-not $journal.rename_completed){throw 'CF_FRESH_UNKNOWN_PLUGIN_FILE'};$completed++}
        }
        foreach($node in Get-ChildItem -LiteralPath $journalDirectory -Force){if($knownJournal -cnotcontains $node.Name){throw 'CF_FRESH_UNKNOWN_JOURNAL_FILE'}}
        if(Test-Path -LiteralPath $plugin){foreach($node in Get-ChildItem -LiteralPath $plugin -Force){if($names -cnotcontains $node.Name -and $knownCandidates -cnotcontains $node.Name){throw 'CF_FRESH_UNKNOWN_PLUGIN_FILE'}}}
        if($completed -gt 0){$state='partial'}
        if($Mode -eq 'Apply') {
            $phase='publish'
            foreach($name in $names){
                $relative='plugin/'+$name;$relativeTarget=$relative;$target=Join-Path $plugin $name;$payload=Join-Path $stageDirectory $relative
                $hash=$inventory.files.PSObject.Properties[$relative].Value
                $null=Set-CfConfigBytesExact -Destination $target -Bytes (Fresh-ReadPinned $payload $hash 2097152) -BeforeSha256 '' -AfterSha256 $hash -OriginalSddl $fileSecurity -AllowCreate -TransactionDirectory $journalDirectory -TargetName $relative
            };$completed=7
        }
        if($completed -eq 7){$state='complete'}
        if((Get-CfConfigHash $config) -cne $configHash -or (Get-CfConfigSddl $config) -cne $configSecurity -or [CfFileBridge.ConfigNativeV1]::Identity($config) -cne $configIdentity){throw 'CF_FRESH_CONFIG_CHANGED'}
        return [pscustomobject]@{state=$state;installed_disabled=($state -ceq 'complete');authorization_required=$true;business_ready=$false;completed_files=$completed;config_unchanged=$true;inventory_sha256=$ExpectedInventorySHA256}
    } catch {
        $code='CF_FRESH_OPERATION_FAILED'
        if($_.Exception.Message -cmatch '^CF_(FRESH|CONFIG)_[A-Z_]{1,80}$'){$code=$_.Exception.Message}
        $safe=[InvalidOperationException]::new($code);$safe.Data['cf_fresh_stage']=$phase;$safe.Data['cf_fresh_state']=$state
        if($relativeTarget -cne 'none'){$safe.Data['cf_target']=$relativeTarget}
        $cause=$_.Exception
        while($null -ne $cause){
            foreach($key in @('cf_rename_completed','cf_staging_exists')){if($cause.Data.Contains($key) -and $cause.Data[$key] -is [bool]){$safe.Data[$key]=$cause.Data[$key]}}
            if($cause.Data.Contains('cf_stage') -and $cause.Data['cf_stage'] -cin @('input_validate','source_validate','candidate_create','candidate_security','candidate_write','candidate_verify','target_recheck','rename','final_verify','journal_validate','journal_create','journal_recover')){$safe.Data['cf_stage']=$cause.Data['cf_stage']}
            $cause=$cause.InnerException
        }
        throw $safe
    } finally {
        if($null -ne $configStream){$configStream.Dispose()}
        foreach($handle in $held.Values){$handle.Dispose()}
    }
}
