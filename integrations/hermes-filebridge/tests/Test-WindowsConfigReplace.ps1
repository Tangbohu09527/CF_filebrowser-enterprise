# Native Windows PowerShell 5.1 regression. Only fresh temporary dummy files.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if ($env:OS -ne 'Windows_NT') { throw 'Windows native test required.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User
$sections = [Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
$utf8 = [Text.UTF8Encoding]::new($false)

function New-PrivateTestDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw 'Test path already exists.' }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($sid)
    foreach ($who in @($sid.Value, 'S-1-5-18')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($who),
            [Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    [IO.Directory]::CreateDirectory($Path, $acl) | Out-Null
}
function Security-Snapshot([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    return [pscustomobject][ordered]@{
        owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        group = $acl.GetGroup([Security.Principal.SecurityIdentifier]).Value
        protected = $acl.AreAccessRulesProtected
        canonical = $acl.AreAccessRulesCanonical
        sddl = $acl.GetSecurityDescriptorSddlForm($sections)
        dacl = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    }
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('cf-replace-test-' + [Guid]::NewGuid().ToString('N'))
New-PrivateTestDirectory $root
$srcDir = Join-Path $root 'source'; New-PrivateTestDirectory $srcDir
$dstDir = Join-Path $root 'destination'; New-PrivateTestDirectory $dstDir
$src = Join-Path $srcDir 'candidate.tmp'
$dst = Join-Path $dstDir 'settings.txt'
[IO.File]::WriteAllText($src, 'CF-REPLACE-NEW', $utf8)
[IO.File]::WriteAllText($dst, 'CF-REPLACE-OLD', $utf8)
foreach ($file in @($src, $dst)) {
    $acl = Get-Acl -LiteralPath $file
    $acl.SetOwner($sid)
    [IO.File]::SetAccessControl($file, $acl)
}
$before = Security-Snapshot $dst
$source = Security-Snapshot $src
Write-Output ('NATIVE_TEST_CONTEXT=' + (@{powershell=$PSVersionTable.PSVersion.ToString(); default_owner=$identity.Owner.Value} | ConvertTo-Json -Compress))
Write-Output ('TARGET_BEFORE=' + ($before | ConvertTo-Json -Compress))
Write-Output ('SOURCE_BEFORE=' + ($source | ConvertTo-Json -Compress))
[IO.File]::Replace($src, $dst, [System.Management.Automation.Language.NullString]::Value, $false)
$after = Security-Snapshot $dst
Write-Output ('TARGET_AFTER=' + ($after | ConvertTo-Json -Compress))
$changed = @('owner','group','protected','canonical','dacl','sddl' | Where-Object { $before.$_ -cne $after.$_ })
Write-Output ('NATIVE_SECURITY_CHANGED_FIELDS=' + (ConvertTo-Json -InputObject $changed -Compress))
if ([IO.File]::ReadAllText($dst) -cne 'CF-REPLACE-NEW' -or (Test-Path -LiteralPath $src)) { throw 'Native byte replacement failed.' }
if ($before.sddl -cne $after.sddl) { throw 'Reproduced: native dummy replacement changed security descriptor.' }
Write-Output 'NATIVE_REPLACE_EXACT_SECURITY=PASS'
