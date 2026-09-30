# Native Windows PowerShell 5.1 regression. Only fresh temporary dummy files.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if ($env:OS -ne 'Windows_NT') { throw 'Windows native test required.' }
. (Join-Path $PSScriptRoot '../windows/ConfigFile.ps1')
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User
$utf8 = [Text.UTF8Encoding]::new($false)
$sections = [Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group

function New-PrivateTestDirectory([string]$Path,[switch]$IncludeAdministrators) {
    if (Test-Path -LiteralPath $Path) { throw 'Test path already exists.' }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($sid)
    $principals=@($sid.Value, 'S-1-5-18');if ($IncludeAdministrators) { $principals+=@('S-1-5-32-544') }
    foreach ($who in $principals) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($who),
            [Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    [IO.Directory]::CreateDirectory($Path, $acl) | Out-Null
}
function Byte-Hash([byte[]]$Data) {
    $h = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($h.ComputeHash($Data))).Replace('-','').ToLowerInvariant() } finally { $h.Dispose() }
}
function New-Target([string]$Name) {
    $dir = Join-Path $root $Name; New-PrivateTestDirectory $dir -IncludeAdministrators:($Name -eq 'inherited-auto')
    $path = Join-Path $dir 'settings.txt'
    if ($Name -eq 'protected-at-create') {
        $security = [Security.AccessControl.FileSecurity]::new()
        $security.SetOwner($sid); $security.SetAccessRuleProtection($true, $false)
        foreach ($who in @($sid.Value, 'S-1-5-18')) {
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($who), [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow))
        }
        $stream = [IO.FileStream]::new($path, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::FullControl,
            [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough, $security)
        try { $bytes=$utf8.GetBytes('CF-REPLACE-OLD');$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
    } else { [IO.File]::WriteAllText($path, 'CF-REPLACE-OLD', $utf8) }
    $acl = Get-Acl -LiteralPath $path; $acl.SetOwner($sid)
    [IO.File]::SetAccessControl($path, $acl)
    return $path
}
function Require([bool]$Condition, [string]$Label) { if (-not $Condition) { throw ('TEST_FAILED: ' + $Label) } }
$root = Join-Path ([IO.Path]::GetTempPath()) ('cf-replace-test-' + [Guid]::NewGuid().ToString('N'))
New-PrivateTestDirectory $root
$oldHash = Byte-Hash ($utf8.GetBytes('CF-REPLACE-OLD'))
$newBytes = $utf8.GetBytes('CF-REPLACE-NEW')
$newHash = Byte-Hash $newBytes
Write-Output ('NATIVE_TEST_CONTEXT=' + (@{powershell=$PSVersionTable.PSVersion.ToString(); owner_is_current_user=($identity.Owner.Value -ceq $sid.Value)} | ConvertTo-Json -Compress))

# Keep the exact failing native operation as a diagnostic. The fixed operation below
# must meet the original byte-for-byte owner/group/DACL requirement; do not normalize it.
$legacy = New-Target 'legacy-destination'
$legacySource = New-Target 'legacy-source'
[IO.File]::WriteAllBytes($legacySource, $newBytes)
$before = Get-CfConfigSddl $legacy
[IO.File]::Replace($legacySource, $legacy, [System.Management.Automation.Language.NullString]::Value, $false)
$after = Get-CfConfigSddl $legacy
Write-Output ('LEGACY_REPLACE_DIAGNOSTIC=' + (@{before_control=[int]([Security.AccessControl.RawSecurityDescriptor]::new($before)).ControlFlags; after_control=[int]([Security.AccessControl.RawSecurityDescriptor]::new($after)).ControlFlags; exact=($before -ceq $after)} | ConvertTo-Json -Compress))

$count = 0
foreach ($mode in @('inherited','protected','explicit-deny','group-owner','protected-at-create','inherited-auto')) {
    $target = New-Target $mode
    $acl = Get-Acl -LiteralPath $target
    if ($mode -eq 'protected') { $acl.SetAccessRuleProtection($true, $true); [IO.File]::SetAccessControl($target, $acl) }
    if ($mode -eq 'explicit-deny') {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-546'),
            [Security.AccessControl.FileSystemRights]::ReadData,
            [Security.AccessControl.AccessControlType]::Deny))
        [IO.File]::SetAccessControl($target, $acl)
    }
    if ($mode -eq 'group-owner') { $acl.SetOwner($identity.Owner); [IO.File]::SetAccessControl($target, $acl) }
    if ($mode -eq 'inherited-auto') {
        $acl.SetSecurityDescriptorSddlForm((Get-CfConfigSddl $target).Replace('D:','D:AI'),$sections)
        [IO.File]::SetAccessControl($target,$acl)
    }
    $security = Get-CfConfigSddl $target
    $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($security)
    if ($mode -eq 'inherited') { Require ([int]$descriptor.ControlFlags -eq 32772) 'legacy inherited control' }
    if ($mode -eq 'protected-at-create') { Require ([int]$descriptor.ControlFlags -eq 36868 -and $descriptor.DiscretionaryAcl.Count -eq 2 -and $descriptor.Group.Value -cne $descriptor.Owner.Value) 'protected legacy control and group' }
    if ($mode -eq 'inherited-auto') { Require ([int]$descriptor.ControlFlags -eq 33796 -and $descriptor.DiscretionaryAcl.Count -eq 3) 'auto inherited control and three ACEs' }
    $result = Set-CfConfigBytesExact -Destination $target -Bytes $newBytes -BeforeSha256 $oldHash -AfterSha256 $newHash -OriginalSddl $security
    Require ($result.hash_verified -and $result.owner_group_dacl_exact) ($mode + ': result')
    Require ((Get-CfConfigSddl $target) -ceq $security) ($mode + ': exact security')
    Require ((Get-CfConfigHash $target) -ceq $newHash) ($mode + ': exact bytes')
    Require (@(Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName($target)) -Filter '.cf-config-*.tmp' -Force).Count -eq 0) ($mode + ': staging removed')
    $count++; Write-Output ('NATIVE_CASE=' + $mode + ':PASS')
}
foreach ($mode in @('wrong-before','wrong-after','wrong-security','hardlink','junction','locked')) {
    $target = New-Target $mode
    $real = $target
    $security = Get-CfConfigSddl $target
    $a = $oldHash; $b = $newHash; $s = $security
    $hold = $null
    if ($mode -eq 'wrong-before') { $a = '0' * 64 }
    if ($mode -eq 'wrong-after') { $b = '0' * 64 }
    if ($mode -eq 'wrong-security') { $s = $security + ' ' }
    if ($mode -eq 'hardlink') { New-Item -ItemType HardLink -Path ($target + '.link') -Target $target | Out-Null }
    if ($mode -eq 'junction') {
        # An actual NTFS reparse point needs no administrator or Developer Mode.
        # The path checker must also refuse a reparse ancestor of a regular file.
        $link = Join-Path $root 'reparse-link'
        New-Item -ItemType Junction -Path $link -Target ([IO.Path]::GetDirectoryName($target)) | Out-Null
        Require ([bool]((Get-Item -LiteralPath $link -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) 'actual junction'
        $target = Join-Path $link 'settings.txt'
    }
    if ($mode -eq 'locked') { $hold = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None) }
    $refused = $false
    try {
        try { Set-CfConfigBytesExact -Destination $target -Bytes $newBytes -BeforeSha256 $a -AfterSha256 $b -OriginalSddl $s | Out-Null }
        catch {
            $refused = $true
            Require ($_.Exception.Message -cmatch '^CF_CONFIG_[A-Z_]+$') ($mode+': sanitized error')
            Require ($_.Exception.Data['cf_rename_completed'] -is [bool] -and -not $_.Exception.Data['cf_rename_completed']) ($mode+': no rename')
            Require ($_.Exception.Data['cf_stage'] -in @('input_validate','source_validate')) ($mode+': safe stage')
        }
    } finally { if ($null -ne $hold) { $hold.Dispose() } }
    Require $refused ($mode + ': expected refusal')
    Require ((Get-CfConfigSddl $real) -ceq $security -and (Get-CfConfigHash $real) -ceq $oldHash) ($mode + ': original untouched')
    $count++; Write-Output ('NATIVE_CASE=' + $mode + ':PASS')
}
# A real sharing violation occurs only at rename. The primitive leaves both the
# original and its identity-pinned journal candidate intact, then resumes safely.
foreach ($mode in @('journal-resume','journal-partial','journal-substitution','journal-target-change','journal-unowned','journal-invalid')) {
    $target=New-Target $mode;$security=Get-CfConfigSddl $target
    $journalDir=Join-Path ([IO.Path]::GetDirectoryName($target)) 'journal';New-PrivateTestDirectory $journalDir
    $arguments=@{Destination=$target;Bytes=$newBytes;BeforeSha256=$oldHash;AfterSha256=$newHash;OriginalSddl=$security;TransactionDirectory=$journalDir;TargetName='plugin/inbound_host.py'}
    $hold=[IO.FileStream]::new($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite))
    $failed=$false
    try { try { Set-CfConfigBytesExact @arguments | Out-Null } catch {
        $failed=$true;Require ($_.Exception.Data['cf_stage'] -ceq 'rename' -and -not $_.Exception.Data['cf_rename_completed'] -and $_.Exception.Data['cf_staging_exists']) ($mode+': actual rename failure')
        Require ($_.Exception.Message -ceq 'CF_CONFIG_OPERATION_FAILED') ($mode+': fixed error code')
    } } finally { $hold.Dispose() }
    Require $failed ($mode+': rename blocked')
    Require ((Get-CfConfigHash $target) -ceq $oldHash -and (Get-CfConfigSddl $target) -ceq $security) ($mode+': target preserved')
    $readArgs=@{};foreach($key in $arguments.Keys) { if ($key -ne 'Bytes') { $readArgs[$key]=$arguments[$key] } }
    $journal=Assert-CfConfigTransactionJournal @readArgs
    Require ($journal.owned_candidate -and $journal.journal_names.Count -eq 2) ($mode+': owned journal')
    $candidate=Join-Path ([IO.Path]::GetDirectoryName($target)) $journal.candidate_name
    if ($mode -eq 'journal-partial') { [IO.File]::WriteAllText($candidate,'partial',$utf8) }
    if ($mode -eq 'journal-substitution') {
        [IO.File]::Move($candidate,($candidate+'.owned'))
        [IO.File]::WriteAllText($candidate,'unknown',$utf8)
    }
    if ($mode -eq 'journal-target-change') { [IO.File]::WriteAllText($target,'concurrent',$utf8) }
    if ($mode -eq 'journal-unowned') {
        $owned=Get-ChildItem -LiteralPath $journalDir -Filter '*.owned.json'
        [IO.File]::Move($owned.FullName,(Join-Path ([IO.Path]::GetDirectoryName($target)) 'saved-owned-record'))
    }
    if ($mode -eq 'journal-invalid') {
        $owned=Get-ChildItem -LiteralPath $journalDir -Filter '*.owned.json'
        [IO.File]::WriteAllText($owned.FullName,'{"partial":',$utf8)
    }
    if ($mode -in @('journal-substitution','journal-target-change','journal-unowned','journal-invalid')) {
        $candidateHash=Get-CfConfigHash $candidate;$targetHash=Get-CfConfigHash $target
        $failed=$false;try { Set-CfConfigBytesExact @arguments | Out-Null } catch { $failed=$true }
        Require ($failed -and (Get-CfConfigHash $candidate) -ceq $candidateHash -and (Get-CfConfigHash $target) -ceq $targetHash) ($mode+': unknown/concurrent preserved')
    } else {
        Set-CfConfigBytesExact @arguments | Out-Null
        $done=Assert-CfConfigTransactionJournal @readArgs
        Require ($done.rename_completed -and -not $done.candidate_exists -and (Get-CfConfigHash $target) -ceq $newHash -and (Get-CfConfigSddl $target) -ceq $security) ($mode+': resume exact')
        Require ((Set-CfConfigBytesExact @arguments).resumed) ($mode+': completion idempotent')
    }
    $count++;Write-Output ('NATIVE_CASE='+$mode+':PASS')
}
$target=New-Target 'journal-create';$security=Get-CfConfigSddl $target
$newTarget=Join-Path ([IO.Path]::GetDirectoryName($target)) 'new.py'
$journalDir=Join-Path ([IO.Path]::GetDirectoryName($target)) 'journal';New-PrivateTestDirectory $journalDir
$arguments=@{Destination=$newTarget;Bytes=$newBytes;BeforeSha256='';AfterSha256=$newHash;OriginalSddl=$security;TransactionDirectory=$journalDir;TargetName='plugin/inbound_content.py';AllowCreate=$true}
Set-CfConfigBytesExact @arguments | Out-Null
Require ((Get-CfConfigSddl $newTarget) -ceq $security -and (Get-CfConfigHash $newTarget) -ceq $newHash) 'create exact'
Require ((Set-CfConfigBytesExact @arguments).resumed) 'create replay'
$otherJournal=Join-Path ([IO.Path]::GetDirectoryName($target)) 'other-journal';New-PrivateTestDirectory $otherJournal
$arguments.TransactionDirectory=$otherJournal
$failed=$false;try { Set-CfConfigBytesExact @arguments | Out-Null } catch { $failed=$true;Require ($_.Exception.Message -ceq 'CF_CONFIG_TARGET_EXISTS') 'create existing error' }
Require ($failed -and (Get-CfConfigHash $newTarget) -ceq $newHash) 'create never overwrite unknown'
$count++;Write-Output 'NATIVE_CASE=journal-create:PASS'

$target=New-Target 'legacy-residue'
$residue=Join-Path ([IO.Path]::GetDirectoryName($target)) ('.cf-config-'+[Guid]::NewGuid().ToString('N')+'.tmp')
[IO.File]::Copy($target,$residue,$false)
$acl=Get-Acl -LiteralPath $residue;$acl.SetSecurityDescriptorSddlForm((Get-CfConfigSddl $target).Replace('D:','D:AI'),$sections);[IO.File]::SetAccessControl($residue,$acl)
$result=Assert-CfConfigLegacyResidue -Path $residue -Target $target
Require ($result.compatible -and -not $result.owned) 'legacy observation is not ownership'
[IO.File]::WriteAllText($target,'new target bytes',$utf8)
Require ((Assert-CfConfigLegacyResidue -Path $residue -Target $target).compatible) 'legacy descriptor verifier allows upgraded target bytes'
$acl=Get-Acl -LiteralPath $residue
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-546'),[Security.AccessControl.FileSystemRights]::ReadData,[Security.AccessControl.AccessControlType]::Allow))
[IO.File]::SetAccessControl($residue,$acl)
$residueSecurity=Get-CfConfigSddl $residue
$failed=$false;try { Assert-CfConfigLegacyResidue -Path $residue -Target $target | Out-Null } catch { $failed=$true }
Require ($failed -and (Get-CfConfigSddl $residue) -ceq $residueSecurity) 'legacy changed ACL preserved'
$count++;Write-Output 'NATIVE_CASE=legacy-residue:PASS'
Write-Output ('NATIVE_CASES_PASSED=' + $count)
Write-Output 'NATIVE_CONFIG_SECURITY_REGRESSION=PASS'
