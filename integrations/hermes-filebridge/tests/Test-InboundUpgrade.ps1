# Real native PS, YAML planner and offline pip/venv; only synthetic private fixtures.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PythonPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) { throw 'Native Windows PowerShell 5.1 required.' }
$driver=Join-Path $PSScriptRoot '../windows/Upgrade-InboundClient.ps1'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$utf8=[Text.UTF8Encoding]::new($false)
$tempBase=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$root=Join-Path $tempBase ('cf-inbound-upgrade-test-'+[Guid]::NewGuid().ToString('N'))
$cases=0;$tokenHandle=$null;$cacheHandle=$null;$runningPython=$null
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
function Refused([scriptblock]$Action,[string]$Name) {
    $failed=$false;try { & $Action | Out-Null } catch { $failed=$true }
    Require $failed ($Name+': must refuse');$script:cases++;Write-Output ('INBOUND_UPGRADE_CASE='+$Name+':PASS')
}
function InvokeUpgrade([string]$Mode,[string]$Directory=$upgrade,[switch]$Stopped) {
    $parameters=@{Mode=$Mode;BundleDirectory=$bundle;ExpectedInventorySHA256=$pin;HermesHome=$profileRoot;
        PythonPath=$PythonPath;UpgradeDirectory=$Directory;HermesStopped=[bool]$Stopped}
    $output=(& $driver @parameters | Out-String)
    Require (-not $output.Contains('synthetic-config-private-sentinel')) 'configuration secret absent from output'
    return ($output | ConvertFrom-Json)
}
try {
    PrivateDirectory $root
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
    $wheelCode | & $PythonPath -I -X utf8 -B - $bundle
    Require ($LASTEXITCODE -eq 0) 'synthetic wheel creation'
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
        Refused { InvokeUpgrade 'Check' } ('invalid-revision-'+$revision)
    }
    [IO.File]::WriteAllText($config,$configuration,$utf8)
    $check=InvokeUpgrade 'Check'
    Require ($check.ok -and -not $check.writes_performed -and -not $check.dependency_ready -and -not (Test-Path -LiteralPath $upgradeParent)) 'default inspection creates nothing including absent parent'
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
    Require ((Hash $config) -ceq $configHash -and (Hash $worker) -ceq $workerHash -and (Get-Acl -LiteralPath $config).Sddl -ceq $configAcl) 'Prepare preserves originals and ACL'
    $runtime=Join-Path $upgrade 'parser-runtime/Scripts/python.exe';Require (Test-Path -LiteralPath $runtime) 'new private parser runtime exists'
    $runtimeHash=Hash $runtime;$runtimeReceiptHash=Hash (Join-Path $upgrade 'runtime.inventory.json')
    $preparedAgain=InvokeUpgrade 'Prepare'
    Require ((Hash $runtime) -ceq $runtimeHash -and (Hash (Join-Path $upgrade 'runtime.inventory.json')) -ceq $runtimeReceiptHash) 'Prepare reuses verified runtime without reinstall'
    $cases++;Write-Output 'INBOUND_UPGRADE_CASE=offline-prepare-resume:PASS'
    Require ((Get-Acl -LiteralPath $upgradeParent).AreAccessRulesProtected) 'new private parent created with protected ACL'
    $ready=InvokeUpgrade 'Check';Require ($ready.ready_to_apply -and -not $ready.writes_performed) 'prepared Check validates runtime read-only'
    $runtimeUnknown=Join-Path $upgrade 'parser-runtime/unknown.py';[IO.File]::WriteAllText($runtimeUnknown,'preserve runtime change',$utf8)
    Refused { InvokeUpgrade 'Prepare' } 'modified-runtime-preserved'
    Require ([IO.File]::ReadAllText($runtimeUnknown) -ceq 'preserve runtime change') 'unknown runtime file untouched'
    Remove-Item -LiteralPath $runtimeUnknown
    $runningInfo=[Diagnostics.ProcessStartInfo]::new();$runningInfo.FileName=$PythonPath
    $runningInfo.Arguments='-I -X utf8 -B -c "import time; time.sleep(30)"';$runningInfo.UseShellExecute=$false;$runningInfo.CreateNoWindow=$true
    $runningPython=[Diagnostics.Process]::Start($runningInfo)
    try {
        Refused { InvokeUpgrade 'Apply' -Stopped } 'active-selected-python-refused'
        Require ((Hash $config) -ceq $configHash -and (Hash (Join-Path $plugin '__init__.py')) -ceq $oldHashes['plugin/__init__.py']) 'active runtime refusal occurs before profile switch'
    } finally {
        if (-not $runningPython.HasExited) { $runningPython.Kill();$runningPython.WaitForExit() };$runningPython.Dispose();$runningPython=$null
    }
    $applied=InvokeUpgrade 'Apply' -Stopped
    Require ($applied.applied -and $applied.existing_worker_preserved -and -not $applied.bundle_worker_matches_existing -and -not $applied.live_restarted) 'explicit narrow apply'
    Require ((Hash $worker) -ceq $workerHash -and (Get-Acl -LiteralPath $config).Sddl -ceq $configAcl) 'Apply keeps old worker and exact config ACL'
    Require ((Hash $config) -ceq (Hash (Join-Path $upgrade 'config.after.yaml'))) 'applied exact reviewed candidate'
    foreach ($name in $names) {
        Require ((Hash (Join-Path $plugin $name)) -ceq $newHashes['plugin/'+$name]) 'new plugin file verified'
        Require ((Hash (Join-Path (Join-Path $upgrade 'plugin.before') $name)) -ceq $oldHashes['plugin/'+$name]) 'old plugin backup retained'
    }
    $resume=InvokeUpgrade 'Resume' -Stopped;Require $resume.applied 'completed resume idempotent'
    $cacheHandle.Dispose();$cacheHandle=$null
    Require ([IO.File]::ReadAllText($cacheFile) -ceq 'opaque original cache') 'existing pycache preserved without read or cleanup'
    [IO.File]::WriteAllBytes((Join-Path $plugin 'inbound.py'),[IO.File]::ReadAllBytes((Join-Path $upgrade 'plugin.before/inbound.py')))
    $partial=InvokeUpgrade 'Resume' -Stopped
    Require ($partial.applied -and (Hash (Join-Path $plugin 'inbound.py')) -ceq $newHashes['plugin/inbound.py']) 'partial known old/new plugin switch resumes'
    $cases++;Write-Output 'INBOUND_UPGRADE_CASE=explicit-apply-idempotent-resume:PASS'
    [IO.File]::AppendAllText($config,"`n# operator change must survive`n",$utf8)
    $modifiedHash=Hash $config
    Refused { InvokeUpgrade 'Resume' -Stopped } 'modified-config-preserved'
    Require ((Hash $config) -ceq $modifiedHash) 'unknown config edits never rolled back'
    Write-Output ('INBOUND_UPGRADE_CASES_PASSED='+$cases)
    Write-Output 'INBOUND_UPGRADE_NATIVE_REGRESSION=PASS'
} finally {
    if ($tokenHandle) { $tokenHandle.Dispose() }
    if ($cacheHandle) { $cacheHandle.Dispose() }
    if ($runningPython) { if (-not $runningPython.HasExited) { $runningPython.Kill();$runningPython.WaitForExit() };$runningPython.Dispose() }
    $resolved=[IO.Path]::GetFullPath($root)
    if (-not $resolved.StartsWith($tempBase+'\',[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -notmatch '^cf-inbound-upgrade-test-[0-9a-f]{32}$') { throw 'Cleanup boundary invalid.' }
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
