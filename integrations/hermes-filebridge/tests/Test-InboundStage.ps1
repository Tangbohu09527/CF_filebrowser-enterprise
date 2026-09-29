# Native staging regression using new temporary dummy bundles only.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw 'Native Windows PowerShell 5.1 required.'
}
$driver=Join-Path $PSScriptRoot '../windows/Manage-InboundClient.ps1'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$utf8=[Text.UTF8Encoding]::new($false)
$tempBase=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$root=Join-Path $tempBase ('cf-inbound-stage-test-'+[Guid]::NewGuid().ToString('N'))
$links=[Collections.Generic.List[string]]::new()
$cases=0
function Require([bool]$Value,[string]$Message) { if (-not $Value) { throw ('TEST_FAILED: '+$Message) } }
function PrivateDirectory([string]$Path) {
    Require (-not (Test-Path -LiteralPath $Path)) 'fixture directory must be new'
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
    foreach ($who in @($sid.Value,'S-1-5-18') | Select-Object -Unique) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($who),[Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    [IO.Directory]::CreateDirectory($Path,$acl) | Out-Null
}
function Hash([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Security([string]$Path) {
    return (Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access)
}
function Refused([scriptblock]$Action,[string]$Label) {
    $denied=$false
    try { & $Action | Out-Null } catch { $denied=$true }
    Require $denied ($Label+': must refuse')
    $script:cases++
    Write-Output ('INBOUND_STAGE_CASE='+$Label+':PASS')
}
function Run([string]$Mode,[string]$Stage,[string]$Source=$source,[string]$Pin=$pin) {
    $arguments=@{Mode=$Mode;SourceDirectory=$Source;StageDirectory=$Stage;ExpectedInventorySHA256=$Pin}
    return (& $driver @arguments | ConvertFrom-Json)
}
function CheckResult($Result,[string]$Label) {
    Require ($Result.staged -eq $true -and $Result.live_enabled -eq $false -and $Result.host_bridge_connected -eq $false) ($Label+': result boundary')
    Require ($Result.source_commit -ceq ('a'*40) -and $Result.inventory_sha256 -ceq $pin) ($Label+': pinned provenance')
}
try {
    PrivateDirectory $root
    $source=Join-Path $root 'source';PrivateDirectory $source
    $sourcePlugin=Join-Path $source 'plugin';PrivateDirectory $sourcePlugin
    $names=@('filebridge-inbound.exe','plugin/__init__.py','plugin/plugin.yaml','plugin/inbound.py',
        'plugin/inbound_control.py','plugin/inbound_directory.py','plugin/inbound_host.py')
    $hashes=[ordered]@{}
    foreach ($name in $names) {
        $path=Join-Path $source $name
        [IO.File]::WriteAllText($path,('public dummy fixture: '+$name),$utf8)
        $hashes[$name]=Hash $path
    }
    $inventory=[ordered]@{schema='cf-inbound-bundle/v1';source_commit=('a'*40);files=$hashes}
    $inventoryPath=Join-Path $source 'inventory.json'
    [IO.File]::WriteAllText($inventoryPath,($inventory | ConvertTo-Json -Depth 4),$utf8)
    $pin=Hash $inventoryPath
    $inspected=& $driver -Mode Inspect -SourceDirectory $source -ExpectedInventorySHA256 $pin | ConvertFrom-Json
    Require ($inspected.verified -and -not $inspected.staged -and $inspected.payload_count -eq 7) 'source Inspect does not require or create stage'
    $stage=Join-Path $root 'release'
    CheckResult (Run 'Stage' $stage) 'stage'
    $worker=Join-Path $stage 'filebridge-inbound.exe'
    $beforeBytes=Hash $worker;$beforeAcl=Security $worker;$beforeWrite=(Get-Item -LiteralPath $worker).LastWriteTimeUtc
    CheckResult (Run 'Resume' $stage) 'resume'
    CheckResult (Run 'Check' $stage) 'check'
    $defaultResult=& $driver -SourceDirectory $source -StageDirectory $stage -ExpectedInventorySHA256 $pin | ConvertFrom-Json
    CheckResult $defaultResult 'default-check'
    Require ($defaultResult.mode -ceq 'Check') 'default mode is read-only Check'
    Require ((Hash $worker) -ceq $beforeBytes -and (Security $worker) -ceq $beforeAcl -and
        (Get-Item -LiteralPath $worker).LastWriteTimeUtc -eq $beforeWrite) 'resume/check preserve existing file and exact ACL'
    $cases++;Write-Output 'INBOUND_STAGE_CASE=stage-resume-check:PASS'

    # The next consumer bundle remains independently pinned and must include
    # both its code and exact dependency inventory. Legacy seven-file bundles
    # above continue through the same Stage/Resume/Check assertions.
    $contentSource=Join-Path $root 'content-source';PrivateDirectory $contentSource
    Copy-Item -LiteralPath $sourcePlugin -Destination $contentSource -Recurse
    Copy-Item -LiteralPath (Join-Path $source 'filebridge-inbound.exe') -Destination $contentSource
    $contentHashes=[ordered]@{}
    foreach ($name in $names) { $contentHashes[$name]=Hash (Join-Path $contentSource $name) }
    foreach ($name in @('plugin/inbound_content.py','requirements-inbound-content.txt','content-wheels.zip')) {
        [IO.File]::WriteAllText((Join-Path $contentSource $name),('consumer dummy fixture: '+$name),$utf8)
        $contentHashes[$name]=Hash (Join-Path $contentSource $name)
    }
    $contentInventory=Join-Path $contentSource 'inventory.json'
    [IO.File]::WriteAllText($contentInventory,([ordered]@{schema='cf-inbound-bundle/v1';source_commit=('a'*40);files=$contentHashes} | ConvertTo-Json -Depth 4),$utf8)
    $contentPin=Hash $contentInventory
    $contentStage=Join-Path $root 'content-release'
    foreach ($action in @('Stage','Resume','Check')) {
        $result=Run $action $contentStage $contentSource $contentPin
        Require ($result.staged -and -not $result.live_enabled -and $result.inventory_sha256 -ceq $contentPin) 'consumer bundle independently verified'
    }
    Require ((Hash (Join-Path $contentStage 'plugin/inbound_content.py')) -ceq $contentHashes['plugin/inbound_content.py']) 'consumer bytes pinned'
    Require ((Hash (Join-Path $contentStage 'requirements-inbound-content.txt')) -ceq $contentHashes['requirements-inbound-content.txt']) 'consumer dependencies pinned'
    Refused { Run 'Check' $contentStage $source $pin } 'consumer-not-accepted-as-legacy-stage'
    $missingRequirements=Join-Path $root 'content-missing-requirements';PrivateDirectory $missingRequirements
    Copy-Item -LiteralPath (Join-Path $contentSource 'plugin') -Destination $missingRequirements -Recurse
    Copy-Item -LiteralPath (Join-Path $contentSource 'filebridge-inbound.exe') -Destination $missingRequirements
    Copy-Item -LiteralPath (Join-Path $contentSource 'content-wheels.zip') -Destination $missingRequirements
    Copy-Item -LiteralPath $contentInventory -Destination $missingRequirements
    Refused { Run 'Stage' (Join-Path $root 'missing-requirements-release') $missingRequirements $contentPin } 'consumer-requires-dependency-list'
    $missingWheels=Join-Path $root 'content-missing-wheels';PrivateDirectory $missingWheels
    Copy-Item -LiteralPath (Join-Path $contentSource 'plugin') -Destination $missingWheels -Recurse
    foreach ($name in @('filebridge-inbound.exe','requirements-inbound-content.txt','inventory.json')) {
        Copy-Item -LiteralPath (Join-Path $contentSource $name) -Destination $missingWheels
    }
    Refused { Run 'Stage' (Join-Path $root 'missing-wheels-release') $missingWheels $contentPin } 'consumer-requires-offline-wheel-payload'
    $cases++;Write-Output 'INBOUND_STAGE_CASE=consumer-stage-resume-check:PASS'
    Refused { Run 'Stage' $stage } 'stage-existing'
    Refused { & $driver -SourceDirectory $source -StageDirectory $stage } 'missing-independent-pin'
    Refused { Run 'Check' $stage $source ('0'*64) } 'wrong-independent-pin'
    Refused { Run 'Check' (Join-Path $root 'missing-check') } 'check-does-not-create'
    Require (-not (Test-Path -LiteralPath (Join-Path $root 'missing-check'))) 'check never creates a missing directory'

    # Authenticated bytes must still satisfy the strict inventory schema.
    $duplicateSource=Join-Path $root 'duplicate-source';PrivateDirectory $duplicateSource
    Copy-Item -LiteralPath $sourcePlugin -Destination $duplicateSource -Recurse
    Copy-Item -LiteralPath (Join-Path $source 'filebridge-inbound.exe') -Destination $duplicateSource
    $duplicateText=[IO.File]::ReadAllText($inventoryPath).Replace('"schema":','"schema":"cf-inbound-bundle/v1","schema":')
    $duplicateInventory=Join-Path $duplicateSource 'inventory.json'
    [IO.File]::WriteAllText($duplicateInventory,$duplicateText,$utf8)
    $duplicatePin=Hash $duplicateInventory
    Refused { Run 'Stage' (Join-Path $root 'duplicate-release') $duplicateSource $duplicatePin } 'duplicate-inventory-key'

    # A partial stage with the same protected ACL is completed without replacing
    # the already staged file. No deletion is used to manufacture this fixture.
    $partial=Join-Path $root 'partial';PrivateDirectory $partial
    $partialFile=Join-Path $partial 'filebridge-inbound.exe'
    [IO.File]::WriteAllBytes($partialFile,[IO.File]::ReadAllBytes($worker))
    $partialAcl=[Security.AccessControl.FileSecurity]::new()
    $partialAcl.SetOwner($sid);$partialAcl.SetAccessRuleProtection($true,$false)
    foreach ($who in @($sid.Value,'S-1-5-18') | Select-Object -Unique) {
        $partialAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($who),[Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    [IO.File]::SetAccessControl($partialFile,$partialAcl)
    $partialWrite=(Get-Item -LiteralPath $partialFile).LastWriteTimeUtc
    CheckResult (Run 'Resume' $partial) 'resume-partial'
    Require ((Get-Item -LiteralPath $partialFile).LastWriteTimeUtc -eq $partialWrite) 'partial resume must reuse exact existing bytes'
    $cases++;Write-Output 'INBOUND_STAGE_CASE=partial-resume:PASS'

    $changed=Join-Path $root 'changed'
    CheckResult (Run 'Stage' $changed) 'changed-setup'
    $changedFile=Join-Path $changed 'filebridge-inbound.exe'
    [IO.File]::WriteAllText($changedFile,'changed bytes must survive',$utf8)
    $changedHash=Hash $changedFile;$changedAcl=Security $changedFile
    Refused { Run 'Resume' $changed } 'changed-target'
    Refused { Run 'Check' $changed } 'changed-target-check'
    Require ((Hash $changedFile) -ceq $changedHash -and (Security $changedFile) -ceq $changedAcl) 'changed target untouched'

    $unknown=Join-Path $stage 'operator-note.txt'
    [IO.File]::WriteAllText($unknown,'preserve unknown data',$utf8)
    $unknownHash=Hash $unknown
    Refused { Run 'Resume' $stage } 'unknown-target'
    Require ((Hash $unknown) -ceq $unknownHash -and (Hash $worker) -ceq $beforeBytes) 'unknown and known target preserved'

    $sourceUnknown=Join-Path $source 'unlisted.txt'
    [IO.File]::WriteAllText($sourceUnknown,'unlisted source retained',$utf8)
    $unknownSourceRelease=Join-Path $root 'unknown-source-release'
    Refused { Run 'Stage' $unknownSourceRelease } 'unknown-source'
    Require ([IO.File]::ReadAllText($sourceUnknown) -ceq 'unlisted source retained' -and
        -not (Test-Path -LiteralPath $unknownSourceRelease)) 'unknown source preserved'
    # Remove only the extra file created by this test, after preservation was checked.
    Remove-Item -LiteralPath $sourceUnknown

    $badParent=Join-Path $root 'broad-parent';PrivateDirectory $badParent
    $acl=Get-Acl -LiteralPath $badParent
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),[Security.AccessControl.FileSystemRights]::Read,
        [Security.AccessControl.AccessControlType]::Allow))
    [IO.Directory]::SetAccessControl($badParent,$acl)
    $badBefore=Security $badParent
    $badStage=Join-Path $badParent 'release'
    Refused { Run 'Stage' $badStage } 'unsafe-parent-acl'
    Require ((Security $badParent) -ceq $badBefore -and -not (Test-Path -LiteralPath $badStage)) 'unsafe parent neither repaired nor written'

    $badFile=Join-Path $partial 'plugin/inbound.py'
    $acl=Get-Acl -LiteralPath $badFile
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),[Security.AccessControl.FileSystemRights]::Read,
        [Security.AccessControl.AccessControlType]::Allow))
    [IO.File]::SetAccessControl($badFile,$acl)
    $badFileSecurity=Security $badFile
    Refused { Run 'Resume' $partial } 'unsafe-existing-file-acl'
    Require ((Security $badFile) -ceq $badFileSecurity) 'existing file ACL not repaired'

    # Junction creation on local NTFS needs no symlink/admin privilege.
    $junction=Join-Path $root 'source-junction'
    New-Item -ItemType Junction -Path $junction -Target $source | Out-Null
    $links.Add($junction)
    $junctionStage=Join-Path $root 'junction-release'
    Refused { Run 'Stage' $junctionStage $junction } 'source-reparse'
    Require (-not (Test-Path -LiteralPath $junctionStage)) 'reparse input never staged'
    $destJunction=Join-Path $root 'dest-junction'
    New-Item -ItemType Junction -Path $destJunction -Target $changed | Out-Null
    $links.Add($destJunction)
    Refused { Run 'Resume' $destJunction } 'destination-reparse'
    Require ((Hash $changedFile) -ceq $changedHash) 'reparse target untouched'

    # Exercise the real native directory handle, not a mock or file lock. The
    # same identity can rename this ancestor without a held handle, proving the
    # rejection below comes from sharing protection rather than ACL denial.
    $renameParent=Join-Path $root 'rename-parent';PrivateDirectory $renameParent
    $renameChild=Join-Path $renameParent 'child';PrivateDirectory $renameChild
    $renameMarker=Join-Path $renameChild 'marker.txt'
    [IO.File]::WriteAllText($renameMarker,'ancestor-lock fixture',$utf8)
    $renameTarget=Join-Path $root 'renamed-parent'
    foreach ($candidate in @($renameParent,$renameTarget)) {
        Require ([IO.Path]::GetFullPath($candidate).StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) 'rename fixture stays within test root'
    }
    [IO.Directory]::Move($renameParent,$renameTarget)
    [IO.Directory]::Move($renameTarget,$renameParent)
    $ancestorHandle=[CfInboundStageNative]::LockDirectory($renameParent)
    try {
        $renameDenied=$false
        try { [IO.Directory]::Move($renameParent,$renameTarget) }
        catch [IO.IOException] { $renameDenied=$true }
        Require $renameDenied 'held ancestor directory must reject rename'
        Require ([IO.File]::ReadAllText($renameMarker) -ceq 'ancestor-lock fixture' -and
            -not (Test-Path -LiteralPath $renameTarget)) 'locked ancestor and child stay in place'
    } finally { $ancestorHandle.Dispose() }
    [IO.Directory]::Move($renameParent,$renameTarget)
    [IO.Directory]::Move($renameTarget,$renameParent)
    $cases++;Write-Output 'INBOUND_STAGE_CASE=ancestor-rename-lock:PASS'

    $oversizeSource=Join-Path $root 'oversize-source';PrivateDirectory $oversizeSource
    Copy-Item -LiteralPath $sourcePlugin -Destination $oversizeSource -Recurse
    Copy-Item -LiteralPath $inventoryPath -Destination $oversizeSource
    $largePath=Join-Path $oversizeSource 'filebridge-inbound.exe'
    $large=[IO.FileStream]::new($largePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $large.SetLength(64L*1024*1024+1) } finally { $large.Dispose() }
    $oversizeRelease=Join-Path $root 'oversize-release'
    Refused { Run 'Stage' $oversizeRelease $oversizeSource } 'oversize-file'
    Require (-not (Test-Path -LiteralPath $oversizeRelease)) 'oversize source never staged'

    $sourceWorker=Join-Path $source 'filebridge-inbound.exe'
    [IO.File]::WriteAllText($sourceWorker,'source changed after inventory signing',$utf8)
    $sourceHash=Hash $sourceWorker
    $sourceChangedStage=Join-Path $root 'source-changed-release'
    Refused { Run 'Stage' $sourceChangedStage } 'changed-source'
    Require ((Hash $sourceWorker) -ceq $sourceHash -and -not (Test-Path -LiteralPath $sourceChangedStage)) 'changed source preserved without destination'
    Write-Output ('INBOUND_STAGE_CASES_PASSED='+$cases)
    Write-Output 'INBOUND_STAGE_NATIVE_REGRESSION=PASS'
} finally {
    # Delete only this test-created root after verifying its absolute boundary.
    # Junctions are removed as entries, never recursively followed.
    $resolved=[IO.Path]::GetFullPath($root)
    if (-not $resolved.StartsWith($tempBase+'\',[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -notmatch '^cf-inbound-stage-test-[0-9a-f]{32}$') { throw 'Test cleanup boundary invalid.' }
    foreach ($link in $links) {
        if (Test-Path -LiteralPath $link) { [IO.Directory]::Delete($link) }
    }
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
