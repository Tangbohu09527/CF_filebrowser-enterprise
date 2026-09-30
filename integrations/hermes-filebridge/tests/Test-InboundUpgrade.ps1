# Real native PS, YAML planner and offline pip/venv; only synthetic private fixtures.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PythonPath,[string]$AlternatePythonPath='',[string]$WheelArchive='',
    [string]$LegacyBundleDirectory='',[string]$LegacyDriver='')
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) { throw 'Native Windows PowerShell 5.1 required.' }
$driver=Join-Path $PSScriptRoot '../windows/Upgrade-InboundClient.ps1'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$utf8=[Text.UTF8Encoding]::new($false)
$tempBase=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$root=Join-Path $tempBase ('cf-inbound-upgrade-test-'+[Guid]::NewGuid().ToString('N'))
$cases=0;$tokenHandle=$null;$cacheHandle=$null;$runningPython=$null;$runningStopPath=$null
function Require([bool]$Value,[string]$Message) { if (-not $Value) { throw ('TEST_FAILED: '+$Message) } }
function Hash([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function PrivateDirectory([string]$Path) {
    Require (-not (Test-Path -LiteralPath $Path)) 'new fixture directory required'
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
    foreach ($who in @($sid.Value,'S-1-5-18') | Select-Object -Unique) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($who),
            [Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    [IO.Directory]::CreateDirectory($Path,$acl) | Out-Null
}
function Refused([scriptblock]$Action,[string]$Name,[string]$Diagnostic='') {
    $failed=$false;try { & $Action | Out-Null } catch {
        $failed=$true
        Require (-not $_.ToString().Contains('synthetic-config-private-sentinel')) 'private configuration absent from failure'
        if ($Diagnostic) {
            $observed=if (@('CF_UPGRADE_SELECTED_HERMES_PYTHON_STILL_RUNNING','CF_UPGRADE_HERMES_HOME_PYTHON_STILL_RUNNING',
                'CF_UPGRADE_PYTHON_STEP_FAILED_NO_PRIVATE_OUTPUT') -ccontains $_.Exception.Message) { $_.Exception.Message } else { $_.Exception.GetType().Name }
            Require ($_.Exception.Message -ceq $Diagnostic) ($Name+': exact safe diagnostic; observed='+$observed)
        }
    }
    Require $failed ($Name+': must refuse');$script:cases++;Write-Output ('INBOUND_UPGRADE_CASE='+$Name+':PASS')
}
function InvokeUpgrade([string]$Mode,[string]$Directory=$upgrade,[switch]$Stopped) {
    $parameters=@{Mode=$Mode;BundleDirectory=$bundle;ExpectedInventorySHA256=$pin;HermesHome=$profileRoot;
        PythonPath=$PythonPath;UpgradeDirectory=$Directory;HermesStopped=[bool]$Stopped}
    $output=(& $driver @parameters | Out-String)
    Require (-not $output.Contains('synthetic-config-private-sentinel')) 'configuration secret absent from output'
    return ($output | ConvertFrom-Json)
}
function StartFixturePython([string]$Executable) {
    $tag=[Guid]::NewGuid().ToString('N')
    $script:runningStopPath=Join-Path $root ($tag+'.stop')
    $ready=Join-Path $root ($tag+'.ready');$program=Join-Path $root ($tag+'.py')
    [IO.File]::WriteAllText($program,@'
import pathlib,sys,time
stop,ready=map(pathlib.Path,sys.argv[1:])
with ready.open('x') as stream: stream.write('ready')
deadline=time.monotonic()+30
while not stop.exists() and time.monotonic()<deadline:
    time.sleep(0.02)
'@,$utf8)
    $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$Executable
    $start.Arguments='-I -X utf8 -B "'+$program+'" "'+$script:runningStopPath+'" "'+$ready+'"'
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $script:runningPython=[Diagnostics.Process]::Start($start)
    $deadline=[DateTime]::UtcNow.AddSeconds(5)
    while (-not (Test-Path -LiteralPath $ready) -and -not $script:runningPython.HasExited -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 20 }
    Require (Test-Path -LiteralPath $ready) 'owned Python fixture reached ready state'
}
function StopFixturePython {
    if ($script:runningPython) {
        try {
            if (-not $script:runningPython.HasExited) {
                [IO.File]::WriteAllText($script:runningStopPath,'stop',$utf8)
                if (-not $script:runningPython.WaitForExit(5000)) {
                    $script:runningPython.Kill();$script:runningPython.WaitForExit()
                    throw 'TEST_FAILED: owned Python fixture did not acknowledge stop'
                }
            }
            Require ($script:runningPython.ExitCode -eq 0) 'owned interpreter and Windows venv launcher exited cleanly'
        } finally { $script:runningPython.Dispose();$script:runningPython=$null }
    }
}
function TestLegacyRecovery {
    Require ($LegacyBundleDirectory -and $LegacyDriver) 'legacy bundle and original driver must be supplied together'
    Require ((Hash (Join-Path $LegacyBundleDirectory 'inventory.json')) -ceq 'c0210fe182748e45be7f446e3f5b78b86935fe984910106f4d9be54bc605f3d0') 'fixed original 6f inventory'
    $legacyInventory=[IO.File]::ReadAllText((Join-Path $LegacyBundleDirectory 'inventory.json')) | ConvertFrom-Json
    Require ($legacyInventory.source_commit -ceq '6f59267ccdfe004ac10777a0be84a0526d6aaab5') 'fixed original 6f source'
    $fixture=Join-Path $root 'legacy';PrivateDirectory $fixture
    $profileRoot=Join-Path $fixture 'profile';PrivateDirectory $profileRoot
    $plugins=Join-Path $profileRoot 'plugins';PrivateDirectory $plugins
    $plugin=Join-Path $plugins 'cf-filebridge';PrivateDirectory $plugin
    foreach ($name in $names) { Copy-Item -LiteralPath (Join-Path $upgrade ('plugin.before/'+$name)) -Destination (Join-Path $plugin $name) }
    # Match the actual protected-at-create shape. The residue is deliberately
    # unjournaled and unowned; only the fixed compatibility policy may classify it.
    $hostFile=Join-Path $plugin 'inbound_host.py';$hostBytes=[IO.File]::ReadAllBytes($hostFile)
    Remove-Item -LiteralPath $hostFile
    $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetOwner($sid);$acl.SetGroup($sid);$acl.SetAccessRuleProtection($true,$false)
    foreach ($who in @($sid.Value,'S-1-5-18') | Select-Object -Unique) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($who),[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))
    }
    $stream=[IO.FileStream]::new($hostFile,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough,$acl)
    try { $stream.Write($hostBytes,0,$hostBytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
    $previous=Join-Path $fixture 'previous';PrivateDirectory $previous
    Copy-Item -LiteralPath $worker -Destination (Join-Path $previous 'filebridge-inbound.exe')
    Copy-Item -LiteralPath ([IO.Path]::Combine([IO.Path]::GetDirectoryName($worker),'inventory.json')) -Destination (Join-Path $previous 'inventory.json')
    $config=Join-Path $profileRoot 'config.yaml'
    [IO.File]::WriteAllText($config,$configuration.Replace($worker,(Join-Path $previous 'filebridge-inbound.exe')),$utf8)
    $upgrade=Join-Path $fixture 'plan'
    $legacyParameters=@{Mode='Prepare';BundleDirectory=$LegacyBundleDirectory;ExpectedInventorySHA256='c0210fe182748e45be7f446e3f5b78b86935fe984910106f4d9be54bc605f3d0';
        HermesHome=$profileRoot;PythonPath=$PythonPath;UpgradeDirectory=$upgrade}
    $prepared=(& $LegacyDriver @legacyParameters | Out-String) | ConvertFrom-Json
    Require ($prepared.prepared -and -not $prepared.applied) 'original 6f code prepared real legacy checkpoint'
    $legacyCheckpointHash=Hash (Join-Path $upgrade 'upgrade.json');$legacyRuntimeHash=Hash (Join-Path $upgrade 'runtime.inventory.json')
    $legacyStageWorkerHash=Hash (Join-Path $upgrade 'bundle/filebridge-inbound.exe')
    Copy-Item -LiteralPath (Join-Path $LegacyBundleDirectory 'plugin/inbound_content.py') -Destination (Join-Path $plugin 'inbound_content.py')
    $residue=Join-Path $plugin ('.cf-config-'+[Guid]::NewGuid().ToString('N')+'.tmp')
    [IO.File]::Copy($hostFile,$residue,$false)
    $targetSddl=(Get-Acl -LiteralPath $hostFile).Sddl
    $residueAcl=Get-Acl -LiteralPath $residue
    $residueAcl.SetSecurityDescriptorSddlForm($targetSddl,[Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access)
    [IO.File]::SetAccessControl($residue,$residueAcl)
    $residueHash=Hash $residue;$residueSddl=(Get-Acl -LiteralPath $residue).Sddl
    Require (([int]([Security.AccessControl.RawSecurityDescriptor]::new($residueSddl)).ControlFlags -bxor [int]([Security.AccessControl.RawSecurityDescriptor]::new($targetSddl)).ControlFlags) -eq 1024) 'real legacy residue differs only in AI control flag'
    $bundle=Join-Path $fixture 'repair';PrivateDirectory $bundle
    Copy-Item -Path (Join-Path $LegacyBundleDirectory '*') -Destination $bundle -Recurse
    # These intentionally unusable replacement worker/wheel bytes must never be
    # selected for a legacy plan. The complete new inventory still verifies.
    [IO.File]::WriteAllText((Join-Path $bundle 'filebridge-inbound.exe'),'repair worker must not replace active old worker',$utf8)
    [IO.File]::WriteAllText((Join-Path $bundle 'content-wheels.zip'),'repair wheels must not enter legacy runtime',$utf8)
    $repairInventory=[IO.File]::ReadAllText((Join-Path $bundle 'inventory.json')) | ConvertFrom-Json
    $repairInventory.source_commit='d'*40
    foreach ($name in @('filebridge-inbound.exe','content-wheels.zip')) { $repairInventory.files.PSObject.Properties[$name].Value=Hash (Join-Path $bundle $name) }
    [IO.File]::WriteAllText((Join-Path $bundle 'inventory.json'),($repairInventory | ConvertTo-Json -Depth 4),$utf8)
    $pin=Hash (Join-Path $bundle 'inventory.json')
    $savedInventory=[IO.File]::ReadAllBytes((Join-Path $bundle 'inventory.json'))
    $newContent=Join-Path $bundle 'plugin/inbound_content.py';$savedContent=[IO.File]::ReadAllBytes($newContent)
    try {
        [IO.File]::AppendAllText($newContent,'# a different consumer cannot claim installer-only compatibility',$utf8)
        $repairInventory.files.'plugin/inbound_content.py'=Hash $newContent
        [IO.File]::WriteAllText((Join-Path $bundle 'inventory.json'),($repairInventory | ConvertTo-Json -Depth 4),$utf8)
        $pin=Hash (Join-Path $bundle 'inventory.json')
        Refused { InvokeUpgrade 'Check' } 'legacy-different-plugin-payload-refused' 'CF_UPGRADE_CHECKPOINT_PAYLOAD_NOT_COMPATIBLE'
    } finally {
        [IO.File]::WriteAllBytes($newContent,$savedContent)
        [IO.File]::WriteAllBytes((Join-Path $bundle 'inventory.json'),$savedInventory)
        $pin=Hash (Join-Path $bundle 'inventory.json')
    }
    try {
        [IO.File]::AppendAllText($residue,'unknown bytes are never classified by basename alone',$utf8)
        Refused { InvokeUpgrade 'Check' } 'legacy-residue-different-bytes-refused'
    } finally { [IO.File]::WriteAllBytes($residue,$hostBytes) }
    $check=InvokeUpgrade 'Check'
    Require ($check.transaction_state -ceq 'partial' -and $check.safe_to_resume -and $check.compatibility_policy -ceq '6f59267-installer-only-repair-v1') 'fixed old plan is proven compatible'
    Require ($check.preserved_legacy_residue_count -eq 1 -and -not $check.legacy_residue_ownership_claimed) 'legacy residue remains explicitly unowned'
    $setupTokens=$null;$setupErrors=$null
    $setupAst=[Management.Automation.Language.Parser]::ParseFile([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../windows/Setup-FileBridge.ps1')),[ref]$setupTokens,[ref]$setupErrors)
    Require ($setupErrors.Count -eq 0) 'unified entry syntax'
    $flowAst=$setupAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-CfSetupFlow'},$true)
    Require ($null -ne $flowAst) 'actual unified flow exists'
    . ([scriptblock]::Create($flowAst.Extent.Text))
    $order=[Collections.Generic.List[string]]::new();$flowValues=@{}
    # Actual plan check/resume/final check use the same partial fixture. Only
    # process lifecycle operations are marked stubs: this fixture has no Hermes
    # service, terminal session or listener to save, stop or restore.
    $dependencies=@{
        Check={ $order.Add('check');return (InvokeUpgrade 'Check') }
        Prepare={ throw 'TEST_FAILED: a proved partial plan must not be prepared again' }
        Save={ $order.Add('save-stub') };Stop={ $order.Add('stop-stub') }
        Apply={ $order.Add('resume');$flowValues.applied=InvokeUpgrade 'Resume' -Stopped;return $flowValues.applied }
        Verify={ $order.Add('verify');$state=InvokeUpgrade 'Check';Require ($state.transaction_state -ceq 'complete' -and $state.safe_to_resume) 'unified final verification requires real complete state' }
        Restore={ $order.Add('restore-stub') }
    }
    $flow=Invoke-CfSetupFlow -Dependencies $dependencies -Approved
    Require ($flow.ok -and $flow.code -ceq 'CF_SETUP_COMPLETE') 'unified flow completes real legacy transaction'
    Require (($order -join ',') -ceq 'check,save-stub,stop-stub,resume,verify,restore-stub') 'unified flow orders check lifecycle resume verification restoration'
    $result=$flowValues.applied
    $script:cases++;Write-Output 'INBOUND_UPGRADE_CASE=unified-flow-real-legacy-resume-lifecycle-stub:PASS'
    Require ($result.transaction_state -ceq 'complete' -and $result.active_inventory_sha256 -ceq $legacyParameters.ExpectedInventorySHA256 -and $result.requested_inventory_sha256 -ceq $pin) 'repair resumes original active release'
    Require ((Hash (Join-Path $upgrade 'upgrade.json')) -ceq $legacyCheckpointHash -and (Hash (Join-Path $upgrade 'runtime.inventory.json')) -ceq $legacyRuntimeHash -and (Hash (Join-Path $upgrade 'bundle/filebridge-inbound.exe')) -ceq $legacyStageWorkerHash) 'legacy immutable plan stage and runtime remain byte exact'
    Require ((Hash $residue) -ceq $residueHash -and (Get-Acl -LiteralPath $residue).Sddl -ceq $residueSddl) 'legacy residue preserved in place with exact bytes and security'
    $complete=InvokeUpgrade 'Check';Require ($complete.transaction_state -ceq 'complete' -and $complete.preserved_legacy_residue_count -eq 1) 'completed legacy recovery remains verifiable with preserved residue'
    $extra=Join-Path $plugin ('.cf-config-'+[Guid]::NewGuid().ToString('N')+'.tmp');[IO.File]::Copy($residue,$extra,$false)
    Refused { InvokeUpgrade 'Check' } 'second-unowned-legacy-residue-refused'
    Require (Test-Path -LiteralPath $extra) 'unowned second residue never deleted'
    $script:cases++;Write-Output 'INBOUND_UPGRADE_CASE=fixed-6f-installer-only-recovery:PASS'
}
try {
    PrivateDirectory $root
    # Load only the local pure diagnostic function. Do not execute the install
    # driver's top-level body or import any official Hermes code for these cases.
    $tokens=$null;$parseErrors=$null
    $driverAst=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $driver),[ref]$tokens,[ref]$parseErrors)
    Require ($parseErrors.Count -eq 0) 'installer syntax'
    $diagnosticAst=$driverAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-CfUpgradeSafePythonFailure'},$true)
    Require ($null -ne $diagnosticAst) 'safe diagnostic function exists'
    . ([scriptblock]::Create($diagnosticAst.Extent.Text))
    $validDiagnostic='{"ok":false,"stage":"config_semantic_plan","error":"existing_profile_revision_invalid"}'
    Require ((Get-CfUpgradeSafePythonFailure $validDiagnostic 'config_semantic_plan') -ceq 'CF_UPGRADE_PYTHON_STEP_FAILED:config_semantic_plan:existing_profile_revision_invalid') 'known failure stage and code'
    $invalidDiagnostics=@(
        $validDiagnostic.Replace('false','"false"'),
        $validDiagnostic.Replace('existing_profile_revision_invalid','synthetic-config-private-sentinel'),
        $validDiagnostic.Replace('config_semantic_plan','synthetic-config-private-sentinel'),
        $validDiagnostic.Replace('{','{"extra":"synthetic-config-private-sentinel",'),
        $validDiagnostic.Replace('"ok":false,','"ok":false,"ok":false,'),
        ('synthetic-config-private-sentinel'+$validDiagnostic),
        ($validDiagnostic+'synthetic-config-private-sentinel'),
        ($validDiagnostic+(' '*513)),
        '{malformed synthetic-config-private-sentinel'
    )
    foreach ($value in $invalidDiagnostics) {
        Require ($null -eq (Get-CfUpgradeSafePythonFailure $value 'config_semantic_plan')) 'unknown diagnostic is suppressed'
    }
    Require ($null -eq (Get-CfUpgradeSafePythonFailure $validDiagnostic 'runtime_dependencies')) 'wrong step diagnostic is suppressed'
    $cases++;Write-Output 'INBOUND_UPGRADE_CASE=bounded-safe-diagnostic-whitelist:PASS'
    $runPythonAst=$driverAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'RunPython'},$true)
    Require ($null -ne $runPythonAst) 'real subprocess wrapper exists'
    . ([scriptblock]::Create($runPythonAst.Extent.Text))
    $profileRoot=$root;$upgrade=$null
    $encoded=[Convert]::ToBase64String($utf8.GetBytes($validDiagnostic))
    $child="import sys,base64;sys.stdout.buffer.write(base64.b64decode('$encoded'));sys.stderr.write('synthetic-config-private-sentinel');sys.exit(1)"
    Refused { RunPython $PythonPath @('-I','-X','utf8','-B','-c',$child) $true 'config_semantic_plan' } 'nonplanner-output-never-promoted' 'CF_UPGRADE_PYTHON_STEP_FAILED_NO_PRIVATE_OUTPUT'
    $child="import sys;sys.stdout.write('synthetic-config-private-sentinel');sys.stderr.write('synthetic-config-private-sentinel')"
    Refused { RunPython $PythonPath @('-I','-X','utf8','-B','-c',$child) } 'malformed-output-never-echoed' 'CF_UPGRADE_PYTHON_RESPONSE_INVALID_NO_PRIVATE_OUTPUT'
    $child="import json,sys;print(json.dumps(sys.dont_write_bytecode and sys.flags.no_user_site==1))"
    Require (RunPython $PythonPath @('-c',$child)) 're-launched children inherit no bytecode and no user site'
    foreach ($functionName in @('Get-CfUpgradePlannerVersion','Assert-CfUpgradeTargetPip')) {
        $functionAst=$driverAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $functionName},$true)
        Require ($null -ne $functionAst) 'runtime preflight function exists'
        . ([scriptblock]::Create($functionAst.Extent.Text))
    }
    foreach ($supported in @(@(3,11,16),@(3,14,7))) {
        $info=[pscustomobject]@{version=$supported;bits=64;platform='win-amd64';implementation='cpython'}
        Require ((Get-CfUpgradePlannerVersion $info) -ceq ($supported -join '.')) 'supported ABI keeps actual patch version'
    }
    foreach ($info in @(
        [pscustomobject]@{version=@(3,12,9);bits=64;platform='win-amd64';implementation='cpython'},
        [pscustomobject]@{version=@(3,11,16);bits=32;platform='win32';implementation='cpython'},
        [pscustomobject]@{version=@(3,14,7);bits=64;platform='win-arm64';implementation='cpython'}
    )) { Refused { Get-CfUpgradePlannerVersion $info } 'unsupported-parser-abi-refused' 'CF_UPGRADE_UNSUPPORTED_PYTHON_ABI' }
    foreach ($unsupportedPip in @($null,'22.2','21.3.1','24.0rc1','synthetic-config-private-sentinel')) {
        Refused { Assert-CfUpgradeTargetPip $unsupportedPip } 'unsupported-planner-pip-refused' 'CF_UPGRADE_PLANNER_PIP_UNSUPPORTED'
    }
    foreach ($supportedPip in @('22.3','24.0','26.2.1')) { Assert-CfUpgradeTargetPip $supportedPip }
    $actualPlannerVersion=RunPython $PythonPath @('-I','-S','-X','utf8','-B','-c',"import json,sys;print(json.dumps('.'.join(map(str,sys.version_info[:3]))))")
    $plannerPackages=RunPython $PythonPath @('-I','-X','utf8','-B','-c',"import json,importlib.metadata;print(json.dumps(sorted((d.metadata.get('Name',''),d.version) for d in importlib.metadata.distributions())))")
    $plannerPackagesJson=$plannerPackages | ConvertTo-Json -Depth 4 -Compress
    & $PythonPath -I -X utf8 -B (Join-Path $PSScriptRoot 'inbound_upgrade_config_checks.py') $root
    Require ($LASTEXITCODE -eq 0) 'configuration and dependency parser regressions'
    $profileRoot=Join-Path $root 'profile';PrivateDirectory $profileRoot
    $plugins=Join-Path $profileRoot 'plugins';PrivateDirectory $plugins
    $plugin=Join-Path $plugins 'cf-filebridge';PrivateDirectory $plugin
    $previous=Join-Path $root 'previous';PrivateDirectory $previous
    $bundle=Join-Path $root 'source';PrivateDirectory $bundle
    $newPlugin=Join-Path $bundle 'plugin';PrivateDirectory $newPlugin
    $names=@('__init__.py','plugin.yaml','inbound.py','inbound_control.py','inbound_directory.py','inbound_host.py')
    $oldHashes=[ordered]@{};$newHashes=[ordered]@{}
    foreach ($name in $names) {
        $oldBytes=if ($name -eq 'plugin.yaml') { "name: cf-filebridge`nversion: '0.3.0'`nkind: standalone`n" } else { '# old synthetic plugin: '+$name }
        $newBytes=if ($name -eq 'plugin.yaml') { "name: cf-filebridge`nversion: '0.4.0'`nkind: standalone`n" } else { '# new synthetic plugin: '+$name }
        [IO.File]::WriteAllText((Join-Path $plugin $name),$oldBytes,$utf8)
        [IO.File]::WriteAllText((Join-Path $newPlugin $name),$newBytes,$utf8)
        $oldHashes['plugin/'+$name]=Hash (Join-Path $plugin $name);$newHashes['plugin/'+$name]=Hash (Join-Path $newPlugin $name)
    }
    [IO.File]::WriteAllText((Join-Path $newPlugin 'inbound_content.py'),'# never imported by this test',$utf8)
    $newHashes['plugin/inbound_content.py']=Hash (Join-Path $newPlugin 'inbound_content.py')
    $worker=Join-Path $previous 'filebridge-inbound.exe';[IO.File]::WriteAllText($worker,'old worker: never executed',$utf8)
    $workerHash=Hash $worker;$oldHashes['filebridge-inbound.exe']=$workerHash
    [IO.File]::WriteAllText((Join-Path $bundle 'filebridge-inbound.exe'),'different release worker: must never replace old',$utf8)
    $newHashes['filebridge-inbound.exe']=Hash (Join-Path $bundle 'filebridge-inbound.exe')
    [IO.File]::WriteAllText((Join-Path $previous 'inventory.json'),([ordered]@{schema='cf-inbound-bundle/v1';source_commit=('a'*40);files=$oldHashes} | ConvertTo-Json -Depth 4),$utf8)
    # A valid local wheel exercises actual --no-index/--require-hashes pip. No
    # package code, server, network endpoint, upstream Hermes or model is run.
    $wheelCode=@'
import hashlib,pathlib,sys,zipfile
root=pathlib.Path(sys.argv[1]); wheel=root/'cf_upgrade_fixture-1.0.0-py3-none-any.whl'
prefix='cf_upgrade_fixture-1.0.0.dist-info/'
with zipfile.ZipFile(wheel,'w') as out:
    out.writestr(prefix+'METADATA','Metadata-Version: 2.1\nName: cf-upgrade-fixture\nVersion: 1.0.0\n'.replace('\\n','\n'))
    out.writestr(prefix+'WHEEL','Wheel-Version: 1.0\nGenerator: isolated-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n'.replace('\\n','\n'))
    out.writestr(prefix+'RECORD',''.join(prefix+name+',,\n' for name in ('METADATA','WHEEL','RECORD')))
raw=wheel.read_bytes()
with zipfile.ZipFile(root/'content-wheels.zip','w') as out: out.writestr(wheel.name,raw)
(root/'requirements-inbound-content.txt').write_text('cf-upgrade-fixture==1.0.0 --hash=sha256:'+hashlib.sha256(raw).hexdigest()+'\n',encoding='utf-8')
wheel.unlink()
'@
    if ($WheelArchive) {
        # Explicit test input only. The installed runtime remains a fresh private
        # fixture; pip enforces the repository's exact production wheel hashes.
        Require ([IO.Path]::IsPathRooted($WheelArchive) -and (Test-Path -LiteralPath $WheelArchive -PathType Leaf)) 'explicit wheel archive required'
        Copy-Item -LiteralPath $WheelArchive -Destination (Join-Path $bundle 'content-wheels.zip')
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot '../requirements-inbound-content.txt') -Destination (Join-Path $bundle 'requirements-inbound-content.txt')
    } else {
        $wheelCode | & $PythonPath -I -X utf8 -B - $bundle
        Require ($LASTEXITCODE -eq 0) 'synthetic wheel creation'
    }
    foreach ($name in @('content-wheels.zip','requirements-inbound-content.txt')) { $newHashes[$name]=Hash (Join-Path $bundle $name) }
    [IO.File]::WriteAllText((Join-Path $bundle 'inventory.json'),([ordered]@{schema='cf-inbound-bundle/v1';source_commit=('b'*40);files=$newHashes} | ConvertTo-Json -Depth 4),$utf8)
    $pin=Hash (Join-Path $bundle 'inventory.json')
    $config=Join-Path $profileRoot 'config.yaml'
    $configuration=@"
# Keep this operator comment and all unrelated values.
model:
  provider: custom
  default: synthetic-model-preserved
  api_key: synthetic-config-private-sentinel
platform_toolsets:
  api_server: [existing-files, existing-create, cf_filebridge_inbound]
plugins:
  enabled: [cf-filebridge, unrelated-plugin]
  entries:
    cf-filebridge:
      settings:
        client_path: 'unchanged-old-filebrowser-client-reference'
        config_path: 'unchanged-old-config-reference'
        inbound_enabled: true
        inbound_host_enabled: true
        inbound_host:
          gateway_origin: 'https://gateway.invalid'
          service_token_env: CF_FILEBRIDGE_HOST_SYNTHETIC_TEST_SECRET
          profile_reference: synthetic-profile
          profile_revision: 1
          work_root: 'unchanged-private-work-root-reference'
          ca_file: 'unchanged-private-ca-reference'
          ca_sha256: '$('c'*64)'
          client_path: '$worker'
          client_sha256: '$workerHash'
          consumer_tools: [existing-consumer]
"@
    [IO.File]::WriteAllText($config,$configuration,$utf8)
    $configHash=Hash $config;$configAcl=(Get-Acl -LiteralPath $config).Sddl
    $token=Join-Path $previous 'token-do-not-read';[IO.File]::WriteAllText($token,'synthetic token not used',$utf8)
    $tokenHandle=[IO.File]::Open($token,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
    $cache=Join-Path $plugin '__pycache__';PrivateDirectory $cache
    $cacheFile=Join-Path $cache 'existing-cpython-cache.pyc';[IO.File]::WriteAllText($cacheFile,'opaque original cache',$utf8)
    $cacheHandle=[IO.File]::Open($cacheFile,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
    $upgradeParent=Join-Path $root 'new-private-parent';$upgrade=Join-Path $upgradeParent 'upgrade'
    foreach ($revision in @("'1'",'true','0','-1')) {
        [IO.File]::WriteAllText($config,$configuration.Replace('profile_revision: 1',('profile_revision: '+$revision)),$utf8)
        Refused { InvokeUpgrade 'Check' } ('invalid-revision-'+$revision) 'CF_UPGRADE_PYTHON_STEP_FAILED:config_semantic_plan:existing_profile_revision_invalid'
    }
    [IO.File]::WriteAllText($config,"model: [synthetic-config-private-sentinel`n",$utf8)
    Refused { InvokeUpgrade 'Check' } 'malformed-yaml-safe-code' 'CF_UPGRADE_PYTHON_STEP_FAILED:config_semantic_plan:configuration_plan_failed'
    [IO.File]::WriteAllText($config,$configuration,$utf8)
    $check=InvokeUpgrade 'Check'
    Require ($check.ok -and -not $check.writes_performed -and -not $check.dependency_ready -and -not (Test-Path -LiteralPath $upgradeParent)) 'default inspection creates nothing including absent parent'
    Require ($check.planner_python_version -ceq $actualPlannerVersion) 'Check reports actual planner version, not serving version'
    Require ((Hash $config) -ceq $configHash -and (Hash $worker) -ceq $workerHash) 'Check preserves config/worker'
    $cases++;Write-Output 'INBOUND_UPGRADE_CASE=read-only-check:PASS'
    Refused { InvokeUpgrade 'Apply' } 'apply-requires-stopped-confirmation'
    $unknown=Join-Path $plugin 'unknown.py';[IO.File]::WriteAllText($unknown,'preserve unknown',$utf8)
    Refused { InvokeUpgrade 'Check' } 'unknown-plugin-preserved'
    Require ([IO.File]::ReadAllText($unknown) -ceq 'preserve unknown') 'unknown file untouched'
    Remove-Item -LiteralPath $unknown
    $conflictParent=Join-Path $root 'existing-unsafe-parent';[IO.Directory]::CreateDirectory($conflictParent) | Out-Null
    $marker=Join-Path $conflictParent 'unknown.txt';[IO.File]::WriteAllText($marker,'operator-owned marker',$utf8)
    $conflictAcl=(Get-Acl -LiteralPath $conflictParent).Sddl
    Refused { InvokeUpgrade 'Prepare' (Join-Path $conflictParent 'upgrade') } 'existing-parent-acl-not-repaired'
    Require ((Get-Acl -LiteralPath $conflictParent).Sddl -ceq $conflictAcl -and [IO.File]::ReadAllText($marker) -ceq 'operator-owned marker') 'unknown parent preserved'
    $prepared=InvokeUpgrade 'Prepare'
    Require ($prepared.prepared -and -not $prepared.applied -and $prepared.dependency_ready) 'offline runtime preparation'
    Require ($prepared.planner_python_version -ceq $actualPlannerVersion) 'Prepare reports actual planner version'
    Require ((Hash $config) -ceq $configHash -and (Hash $worker) -ceq $workerHash -and (Get-Acl -LiteralPath $config).Sddl -ceq $configAcl) 'Prepare preserves originals and ACL'
    $runtime=Join-Path $upgrade 'parser-runtime/Scripts/python.exe';Require (Test-Path -LiteralPath $runtime) 'new private parser runtime exists'
    $runtimeHash=Hash $runtime;$runtimeReceiptHash=Hash (Join-Path $upgrade 'runtime.inventory.json')
    $hasPip=RunPython $runtime @('-I','-X','utf8','-B','-c',"import json,importlib.util;print(json.dumps(importlib.util.find_spec('pip') is not None))")
    Require (-not $hasPip) 'parser runtime does not install pip or setuptools bootstrap'
    $currentPlannerPackages=RunPython $PythonPath @('-I','-X','utf8','-B','-c',"import json,importlib.metadata;print(json.dumps(sorted((d.metadata.get('Name',''),d.version) for d in importlib.metadata.distributions())))")
    Require (($currentPlannerPackages | ConvertTo-Json -Depth 4 -Compress) -ceq $plannerPackagesJson) 'planner package inventory unchanged by target offline install'
    $preparedAgain=InvokeUpgrade 'Prepare'
    Require ((Hash $runtime) -ceq $runtimeHash -and (Hash (Join-Path $upgrade 'runtime.inventory.json')) -ceq $runtimeReceiptHash) 'Prepare reuses verified runtime without reinstall'
    $cases++;Write-Output 'INBOUND_UPGRADE_CASE=offline-prepare-resume:PASS'
    Require ((Get-Acl -LiteralPath $upgradeParent).AreAccessRulesProtected) 'new private parent created with protected ACL'
    $ready=InvokeUpgrade 'Check';Require ($ready.ready_to_apply -and -not $ready.writes_performed -and $ready.transaction_state -ceq 'prepared' -and $ready.safe_to_resume) 'prepared Check validates runtime read-only'
    $checkpointHash=Hash (Join-Path $upgrade 'upgrade.json')
    foreach ($relative in @('plugin.before/inbound_host.py','config.after.yaml','bundle/plugin/inbound_content.py')) {
        $tampered=Join-Path $upgrade $relative;$saved=[IO.File]::ReadAllBytes($tampered)
        try {
            [IO.File]::AppendAllText($tampered,'synthetic-owned-fixture-tamper',$utf8)
            Refused { InvokeUpgrade 'Check' } ('checkpoint-integrity-'+$relative.Replace('/','-'))
        } finally { [IO.File]::WriteAllBytes($tampered,$saved) }
    }
    $journal=Join-Path $upgrade 'candidate-journal';PrivateDirectory $journal
    $unknownJournal=Join-Path $journal 'unknown.json';[IO.File]::WriteAllText($unknownJournal,'preserve unknown journal',$utf8)
    Refused { InvokeUpgrade 'Check' } 'unknown-journal-preserved'
    Require ([IO.File]::ReadAllText($unknownJournal) -ceq 'preserve unknown journal') 'unknown journal never deleted'
    Remove-Item -LiteralPath $unknownJournal
    $runtimeUnknown=Join-Path $upgrade 'parser-runtime/unknown.py';[IO.File]::WriteAllText($runtimeUnknown,'preserve runtime change',$utf8)
    Refused { InvokeUpgrade 'Prepare' } 'modified-runtime-preserved' 'CF_UPGRADE_PYTHON_STEP_FAILED:runtime_inventory:runtime_modified_or_unknown'
    Require ([IO.File]::ReadAllText($runtimeUnknown) -ceq 'preserve runtime change') 'unknown runtime file untouched'
    Remove-Item -LiteralPath $runtimeUnknown
    StartFixturePython $PythonPath
    try {
        Refused { InvokeUpgrade 'Apply' -Stopped } 'active-selected-python-refused'
        Require ((Hash $config) -ceq $configHash -and (Hash (Join-Path $plugin '__init__.py')) -ceq $oldHashes['plugin/__init__.py']) 'active runtime refusal occurs before profile switch'
    } finally {
        StopFixturePython
    }
    if ($AlternatePythonPath) {
        # Prove that a serving interpreter different from the planner cannot
        # bypass the stopped check. This is a new synthetic venv, never Hermes.
        $alternateRoot=Join-Path $profileRoot 'other-serving-runtime';PrivateDirectory $alternateRoot
        & $AlternatePythonPath -I -X utf8 -B -m venv --without-pip $alternateRoot
        Require ($LASTEXITCODE -eq 0) 'independent alternate serving fixture'
        StartFixturePython (Join-Path $alternateRoot 'Scripts/python.exe')
        try {
            Refused { InvokeUpgrade 'Apply' -Stopped } 'different-serving-runtime-under-hermes-home-refused' 'CF_UPGRADE_HERMES_HOME_PYTHON_STILL_RUNNING'
            Require ((Hash $config) -ceq $configHash -and (Hash (Join-Path $plugin '__init__.py')) -ceq $oldHashes['plugin/__init__.py']) 'alternate serving runtime refusal preserves profile'
        } finally {
            StopFixturePython
        }
    }
    $applyOrder=@('inbound_content.py','inbound.py','inbound_control.py','inbound_directory.py','inbound_host.py','__init__.py','plugin.yaml','config.yaml')
    # A real NTFS sharing violation interrupts each existing-file rename. The
    # read handle permits all preflight verification but denies write/delete.
    # Release only our own handle, then prove the journaled partial transaction
    # is safe to resume. No production file or process participates.
    foreach ($blockedName in $applyOrder | Select-Object -Skip 1) {
        $blocked=if ($blockedName -ceq 'config.yaml') { $config } else { Join-Path $plugin $blockedName }
        $relative=if ($blockedName -ceq 'config.yaml') { $blockedName } else { 'plugin/'+$blockedName }
        $lock=[IO.File]::Open($blocked,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $failed=$false
        try {
            try { InvokeUpgrade 'Resume' -Stopped | Out-Null } catch {
                $failed=$true
                Require ($_.Exception.Data['cf_target'] -ceq $relative) 'failure identifies only fixed relative target'
                Require ($_.Exception.Data['cf_stage'] -ceq 'rename') 'real rename interruption reached expected stage'
                Require (-not $_.Exception.Data['cf_rename_completed'] -and $_.Exception.Data['cf_staging_exists']) 'owned candidate retained before rename'
                Require (-not $_.ToString().Contains('synthetic-config-private-sentinel') -and -not $_.Exception.Message.Contains($root)) 'safe failure contains no private data or absolute path'
            }
        } finally { $lock.Dispose() }
        Require $failed 'sharing lock must cause real interruption'
        $beforeBlocked=$true
        foreach ($name in $applyOrder | Where-Object { $_ -cne 'config.yaml' }) {
            if ($name -ceq $blockedName) { $beforeBlocked=$false }
            $expected=if ($beforeBlocked) { $newHashes['plugin/'+$name] } else { $oldHashes['plugin/'+$name] }
            Require ((Hash (Join-Path $plugin $name)) -ceq $expected) 'only proven completed prefix changed'
        }
        Require ((Hash $config) -ceq $configHash) 'configuration remains old through all interrupted plugin writes'
        $partialCheck=InvokeUpgrade 'Check'
        Require ($partialCheck.transaction_state -ceq 'partial' -and $partialCheck.safe_to_resume -and -not $partialCheck.writes_performed) 'partial Check validates journal and recovery without writes'
        Require ((Hash (Join-Path $upgrade 'upgrade.json')) -ceq $checkpointHash -and (Hash (Join-Path $upgrade 'runtime.inventory.json')) -ceq $runtimeReceiptHash) 'immutable checkpoint and runtime receipt retained'
        $cases++;Write-Output ('INBOUND_UPGRADE_CASE=interrupted-rename-'+$blockedName+':PASS')
    }
    $applied=InvokeUpgrade 'Apply' -Stopped
    Require ($applied.applied -and $applied.existing_worker_preserved -and -not $applied.bundle_worker_matches_existing -and -not $applied.live_restarted) 'explicit narrow apply'
    Require ($applied.planner_python_version -ceq $actualPlannerVersion) 'Apply reports actual planner version'
    Require ((Hash $worker) -ceq $workerHash -and (Get-Acl -LiteralPath $config).Sddl -ceq $configAcl) 'Apply keeps old worker and exact config ACL'
    Require ((Hash $config) -ceq (Hash (Join-Path $upgrade 'config.after.yaml'))) 'applied exact reviewed candidate'
    foreach ($name in $names) {
        Require ((Hash (Join-Path $plugin $name)) -ceq $newHashes['plugin/'+$name]) 'new plugin file verified'
        Require ((Hash (Join-Path (Join-Path $upgrade 'plugin.before') $name)) -ceq $oldHashes['plugin/'+$name]) 'old plugin backup retained'
    }
    $resume=InvokeUpgrade 'Resume' -Stopped;Require ($resume.applied -and $resume.transaction_state -ceq 'complete' -and $resume.safe_to_resume) 'completed resume idempotent'
    $completeCheck=InvokeUpgrade 'Check';Require ($completeCheck.transaction_state -ceq 'complete' -and $completeCheck.safe_to_resume) 'complete is distinguished from prepared and partial'
    $cacheHandle.Dispose();$cacheHandle=$null
    Require ([IO.File]::ReadAllText($cacheFile) -ceq 'opaque original cache') 'existing pycache preserved without read or cleanup'
    [IO.File]::WriteAllBytes((Join-Path $plugin 'inbound.py'),[IO.File]::ReadAllBytes((Join-Path $upgrade 'plugin.before/inbound.py')))
    Refused { InvokeUpgrade 'Resume' -Stopped } 'completed-owned-target-modification-preserved'
    Require ((Hash (Join-Path $plugin 'inbound.py')) -ceq $oldHashes['plugin/inbound.py']) 'changed completed target is not silently overwritten'
    [IO.File]::WriteAllBytes((Join-Path $plugin 'inbound.py'),[IO.File]::ReadAllBytes((Join-Path $newPlugin 'inbound.py')))
    $cases++;Write-Output 'INBOUND_UPGRADE_CASE=explicit-apply-idempotent-resume:PASS'
    if ($LegacyBundleDirectory -or $LegacyDriver) { TestLegacyRecovery }
    [IO.File]::AppendAllText($config,"`n# operator change must survive`n",$utf8)
    $modifiedHash=Hash $config
    Refused { InvokeUpgrade 'Resume' -Stopped } 'modified-config-preserved'
    Require ((Hash $config) -ceq $modifiedHash) 'unknown config edits never rolled back'
    Write-Output ('INBOUND_UPGRADE_CASES_PASSED='+$cases)
    Write-Output 'INBOUND_UPGRADE_NATIVE_REGRESSION=PASS'
} finally {
    if ($tokenHandle) { $tokenHandle.Dispose() }
    if ($cacheHandle) { $cacheHandle.Dispose() }
    StopFixturePython
    $resolved=[IO.Path]::GetFullPath($root)
    if (-not $resolved.StartsWith($tempBase+'\',[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -notmatch '^cf-inbound-upgrade-test-[0-9a-f]{32}$') { throw 'Cleanup boundary invalid.' }
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
