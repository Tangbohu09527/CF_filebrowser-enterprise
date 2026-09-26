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
function Byte-Hash([byte[]]$Data) {
    $h = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($h.ComputeHash($Data))).Replace('-','').ToLowerInvariant() } finally { $h.Dispose() }
}
function New-Target([string]$Name) {
    $dir = Join-Path $root $Name; New-PrivateTestDirectory $dir
    $path = Join-Path $dir 'settings.txt'
    [IO.File]::WriteAllText($path, 'CF-REPLACE-OLD', $utf8)
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
Write-Output ('NATIVE_TEST_CONTEXT=' + (@{powershell=$PSVersionTable.PSVersion.ToString(); default_owner=$identity.Owner.Value} | ConvertTo-Json -Compress))

# Keep the exact failing native operation as a diagnostic. The fixed operation below
# must meet the original byte-for-byte owner/group/DACL requirement; do not normalize it.
$legacy = New-Target 'legacy-destination'
$legacySource = New-Target 'legacy-source'
[IO.File]::WriteAllBytes($legacySource, $newBytes)
$before = Get-CfConfigSddl $legacy
[IO.File]::Replace($legacySource, $legacy, [System.Management.Automation.Language.NullString]::Value, $false)
$after = Get-CfConfigSddl $legacy
Write-Output ('LEGACY_REPLACE_DIAGNOSTIC=' + (@{before=$before; after=$after; exact=($before -ceq $after)} | ConvertTo-Json -Compress))

$count = 0
foreach ($mode in @('inherited','protected','explicit-deny','group-owner')) {
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
    $security = Get-CfConfigSddl $target
    $result = Set-CfConfigBytesExact -Destination $target -Bytes $newBytes -BeforeSha256 $oldHash -AfterSha256 $newHash -OriginalSddl $security
    Require ($result.hash_verified -and $result.owner_group_dacl_exact) ($mode + ': result')
    Require ((Get-CfConfigSddl $target) -ceq $security) ($mode + ': exact security')
    Require ((Get-CfConfigHash $target) -ceq $newHash) ($mode + ': exact bytes')
    Require (@(Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName($target)) -Filter '.cf-config-*.tmp' -Force).Count -eq 0) ($mode + ': staging removed')
    $count++; Write-Output ('NATIVE_CASE=' + $mode + ':PASS')
}
foreach ($mode in @('wrong-before','wrong-after','wrong-security','hardlink','symlink','locked')) {
    $target = New-Target $mode
    $real = $target
    $security = Get-CfConfigSddl $target
    $a = $oldHash; $b = $newHash; $s = $security
    $hold = $null
    if ($mode -eq 'wrong-before') { $a = '0' * 64 }
    if ($mode -eq 'wrong-after') { $b = '0' * 64 }
    if ($mode -eq 'wrong-security') { $s = $security + ' ' }
    if ($mode -eq 'hardlink') { New-Item -ItemType HardLink -Path ($target + '.link') -Target $target | Out-Null }
    if ($mode -eq 'symlink') {
        $link = $target + '.symlink'; New-Item -ItemType SymbolicLink -Path $link -Target $target | Out-Null
        $target = $link
    }
    if ($mode -eq 'locked') { $hold = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None) }
    $refused = $false
    try {
        try { Set-CfConfigBytesExact -Destination $target -Bytes $newBytes -BeforeSha256 $a -AfterSha256 $b -OriginalSddl $s | Out-Null }
        catch { $refused = $true }
    } finally { if ($null -ne $hold) { $hold.Dispose() } }
    Require $refused ($mode + ': expected refusal')
    Require ((Get-CfConfigSddl $real) -ceq $security -and (Get-CfConfigHash $real) -ceq $oldHash) ($mode + ': original untouched')
    $count++; Write-Output ('NATIVE_CASE=' + $mode + ':PASS')
}
Write-Output ('NATIVE_CASES_PASSED=' + $count)
Write-Output 'NATIVE_CONFIG_SECURITY_REGRESSION=PASS'
