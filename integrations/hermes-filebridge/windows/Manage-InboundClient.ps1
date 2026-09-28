# Stage an independently pinned inbound bundle. Never installs/enables Hermes.
[CmdletBinding()]
param(
    [ValidateSet('Stage','Resume','Check','SelfTest')][string]$Mode='Check',
    [string]$SourceDirectory='',
    [string]$StageDirectory='',
    [string]$ExpectedInventorySHA256=''
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw 'Native Windows PowerShell 5.1 required.'
}
if ($Mode -eq 'SelfTest') {
    & (Join-Path $PSScriptRoot '../tests/Test-InboundStage.ps1')
    return
}
if (-not $SourceDirectory -or -not $StageDirectory -or $ExpectedInventorySHA256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'SourceDirectory, StageDirectory and independently verified ExpectedInventorySHA256 are required.'
}

if (-not ('CfInboundStageNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class CfInboundStageNative {
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {
        public int Length; public IntPtr Descriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool Inherit;
    }
    [StructLayout(LayoutKind.Sequential)] struct FileInfo {
        public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation;
        public System.Runtime.InteropServices.ComTypes.FILETIME Access;
        public System.Runtime.InteropServices.ComTypes.FILETIME Write;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CreateDirectoryW(string path, ref SecurityAttributes attributes);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);
    public static void CreateDirectory(string path, byte[] descriptor) {
        IntPtr buffer = Marshal.AllocHGlobal(descriptor.Length);
        try {
            Marshal.Copy(descriptor, 0, buffer, descriptor.Length);
            SecurityAttributes sa = new SecurityAttributes();
            sa.Length=Marshal.SizeOf(typeof(SecurityAttributes)); sa.Descriptor=buffer; sa.Inherit=false;
            if (!CreateDirectoryW(path, ref sa)) throw new Win32Exception(Marshal.GetLastWin32Error());
        } finally { Marshal.FreeHGlobal(buffer); }
    }
    public static SafeFileHandle LockDirectory(string path) {
        // FILE_LIST_DIRECTORY | READ_ATTRIBUTES. Attribute-only access does not
        // participate in delete sharing and cannot stop ancestor rename. The
        // directory read right makes omitting SHARE_DELETE effective;
        // OPEN_REPARSE_POINT makes the inspected handle authoritative.
        SafeFileHandle handle=CreateFileW(path, 0x81, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (handle.IsInvalid) { int error=Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
        try { CheckDirectory(handle); return handle; } catch { handle.Dispose(); throw; }
    }
    public static void CheckDirectory(SafeFileHandle handle) {
        FileInfo info;
        if (!GetFileInformationByHandle(handle, out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
        if ((info.Attributes & 0x400) != 0 || (info.Attributes & 0x10) == 0)
            throw new InvalidOperationException("Reparse or non-directory path refused.");
    }
    public static SafeFileHandle OpenFileRead(string path) {
        SafeFileHandle handle=CreateFileW(path, 0x80000000, 1, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
        if (handle.IsInvalid) { int error=Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
        try { CheckFile(handle); return handle; } catch { handle.Dispose(); throw; }
    }
    public static void CheckFile(SafeFileHandle handle) {
        FileInfo info;
        if (!GetFileInformationByHandle(handle, out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
        if ((info.Attributes & (0x400|0x10)) != 0 || info.Links != 1)
            throw new InvalidOperationException("Reparse, directory or hardlinked file refused.");
    }
}
'@
}
$operatorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$maxFile=64L*1024*1024
$fileNames=@('filebridge-inbound.exe','plugin/__init__.py','plugin/plugin.yaml','plugin/inbound.py',
    'plugin/inbound_control.py','plugin/inbound_directory.py','plugin/inbound_host.py')
$allNames=@($fileNames)+@('inventory.json')
$heldDirectories=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)

function Normalize-LocalAbsolute([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.Substring(2).Contains(':') -or $Path.Contains('~')) {
        throw 'Only explicit absolute local drive paths are supported; no UNC, device paths or streams.'
    }
    if ($Path -match '[\\/](\.|\.\.)([\\/]|$)' -or $Path -match '[ .]([\\/]|$)') {
        throw 'Ambiguous path components refused.'
    }
    $full=[IO.Path]::GetFullPath($Path).TrimEnd('\','/')
    if ($full.Length -lt 4) { throw 'Drive roots cannot be source or destination directories.' }
    $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -ne 'NTFS') {
        throw 'A local fixed NTFS drive is required.'
    }
    return $full
}
function Assert-Node([string]$Path,[bool]$Directory) {
    $item=Get-Item -LiteralPath $Path -Force
    if ([bool]$item.PSIsContainer -ne $Directory -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Wrong node type or reparse point refused.'
    }
}
function Hold-Directory([string]$Path) {
    if ($heldDirectories.ContainsKey($Path)) { [CfInboundStageNative]::CheckDirectory($heldDirectories[$Path]); return }
    $parent=[IO.Directory]::GetParent($Path)
    if ($null -ne $parent) { Hold-Directory $parent.FullName }
    $handle=[CfInboundStageNative]::LockDirectory($Path)
    $heldDirectories.Add($Path,$handle)
}
function New-PrivateSecurity([bool]$Directory) {
    $acl=if ($Directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($operatorSid))
    $acl.SetAccessRuleProtection($true,$false)
    $inherit=if ($Directory) { [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($sid in @($operatorSid,'S-1-5-18') | Select-Object -Unique) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,
            $inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    return $acl
}
function Assert-PrivateAcl([string]$Path,[bool]$Directory,[bool]$Parent=$false) {
    Assert-Node $Path $Directory
    $acl=Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected -or -not $acl.AreAccessRulesCanonical) { throw 'Private protected canonical DACL required; no ACL repair performed.' }
    $allowed=@($operatorSid,'S-1-5-18')
    if ($Parent) { $allowed+=@('S-1-5-32-544') }
    $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (($Parent -and $allowed -notcontains $owner) -or (-not $Parent -and $owner -ne $operatorSid)) {
        throw 'Unexpected owner; ownership is never repaired.'
    }
    $inherit=if ($Directory) { [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit } else { [Security.AccessControl.InheritanceFlags]::None }
    $seen=@{}
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        $sid=$rule.IdentityReference.Value
        if ($allowed -notcontains $sid -or $seen.ContainsKey($sid) -or $rule.IsInherited -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne $inherit -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw 'DACL differs from the exact private full-control policy.'
        }
        $seen[$sid]=$true
    }
    foreach ($sid in @($operatorSid,'S-1-5-18')) { if (-not $seen.ContainsKey($sid)) { throw 'Required private SID missing.' } }
}
function Create-PrivateDirectory([string]$Path) {
    Hold-Directory ([IO.Path]::GetDirectoryName($Path))
    $acl=New-PrivateSecurity $true
    [CfInboundStageNative]::CreateDirectory($Path,$acl.GetSecurityDescriptorBinaryForm())
    Hold-Directory $Path
    Assert-PrivateAcl $Path $true
}
function Stream-Hash([IO.Stream]$Stream) {
    $Stream.Position=0
    $hash=[Security.Cryptography.SHA256]::Create()
    try { $value=([BitConverter]::ToString($hash.ComputeHash($Stream))).Replace('-','').ToLowerInvariant() }
    finally { $hash.Dispose() }
    $Stream.Position=0
    return $value
}
function Open-VerifiedFile([string]$Path,[string]$Expected,[long]$Limit=$maxFile) {
    Hold-Directory ([IO.Path]::GetDirectoryName($Path))
    Assert-Node $Path $false
    $fileHandle=[CfInboundStageNative]::OpenFileRead($Path)
    try { $stream=[IO.FileStream]::new($fileHandle,[IO.FileAccess]::Read) }
    catch { $fileHandle.Dispose(); throw }
    try {
        [CfInboundStageNative]::CheckFile($stream.SafeFileHandle)
        Assert-Node $Path $false
        if ($stream.Length -gt $Limit) { throw 'File exceeds allowed size.' }
        if ((Stream-Hash $stream) -cne $Expected.ToLowerInvariant()) { throw 'File SHA-256 differs from the independent inventory.' }
        return $stream
    } catch { $stream.Dispose(); throw }
}
function Assert-KnownTree([string]$Root,[bool]$Complete,[bool]$Private) {
    Hold-Directory $Root
    if ($Private) { Assert-PrivateAcl $Root $true }
    foreach ($child in @(Get-ChildItem -LiteralPath $Root -Force)) {
        if ($child.Name -ceq 'plugin') {
            Assert-Node $child.FullName $true
            Hold-Directory $child.FullName
            if ($Private) { Assert-PrivateAcl $child.FullName $true }
            foreach ($leaf in @(Get-ChildItem -LiteralPath $child.FullName -Force)) {
                if (@('__init__.py','plugin.yaml','inbound.py','inbound_control.py','inbound_directory.py','inbound_host.py') -cnotcontains $leaf.Name) { throw 'Unknown file preserved; staging refused.' }
                Assert-Node $leaf.FullName $false
                if ($Private) { Assert-PrivateAcl $leaf.FullName $false }
            }
        } elseif (@('filebridge-inbound.exe','inventory.json') -ccontains $child.Name) {
            Assert-Node $child.FullName $false
            if ($Private) { Assert-PrivateAcl $child.FullName $false }
        } else { throw 'Unknown file preserved; staging refused.' }
    }
    if ($Complete) { foreach ($name in $allNames) { Assert-Node (Join-Path $Root $name) $false } }
}
function Read-Inventory([string]$Root,[string]$Expected) {
    $stream=Open-VerifiedFile (Join-Path $Root 'inventory.json') $Expected 65536
    try {
        $bytes=[byte[]]::new([int]$stream.Length)
        $offset=0
        while ($offset -lt $bytes.Length) {
            $count=$stream.Read($bytes,$offset,$bytes.Length-$offset)
            if ($count -eq 0) { throw 'Incomplete inventory read.' }
            $offset+=$count
        }
        if ((Stream-Hash $stream) -cne $Expected.ToLowerInvariant()) { throw 'Inventory changed while reading.' }
    } finally { $stream.Dispose() }
    $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xFEFF)
    # This fixed ASCII schema needs no JSON string escapes. Reject duplicates
    # before ConvertFrom-Json (PowerShell 5.1 otherwise silently keeps one value).
    if ($text.Contains('\')) { throw 'Escaped inventory strings are unsupported.' }
    $keys=@([regex]::Matches($text,'"([^"\\]*)"\s*:') | ForEach-Object { $_.Groups[1].Value })
    $expectedKeys=@('schema','source_commit','files')+$fileNames
    if ($keys.Count -ne $expectedKeys.Count) { throw 'Inventory keys differ.' }
    foreach ($key in $expectedKeys) { if (@($keys | Where-Object { $_ -ceq $key }).Count -ne 1) { throw 'Duplicate or missing inventory key.' } }
    $inventory=$text | ConvertFrom-Json
    if ($inventory -isnot [Management.Automation.PSCustomObject] -or
        @($inventory.PSObject.Properties.Name).Count -ne 3 -or
        $inventory.schema -cne 'cf-inbound-bundle/v1' -or
        $inventory.source_commit -isnot [string] -or $inventory.source_commit -notmatch '^[0-9a-fA-F]{40}$' -or
        $inventory.files -isnot [Management.Automation.PSCustomObject] -or @($inventory.files.PSObject.Properties.Name).Count -ne $fileNames.Count) {
        throw 'Invalid inventory schema or source commit.'
    }
    $hashes=@{'inventory.json'=$Expected.ToLowerInvariant()}
    foreach ($name in $fileNames) {
        $value=$inventory.files.PSObject.Properties[$name]
        if ($null -eq $value -or $value.Value -isnot [string] -or $value.Value -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid inventory file hash.' }
        $hashes[$name]=$value.Value.ToLowerInvariant()
    }
    return @{commit=$inventory.source_commit.ToLowerInvariant();hashes=$hashes}
}
function Verify-Files([string]$Root,[hashtable]$Hashes,[bool]$Complete) {
    foreach ($name in $allNames) {
        $path=Join-Path $Root $name
        if (-not (Test-Path -LiteralPath $path)) {
            if ($Complete) { throw 'Required bundle file missing.' }
            continue
        }
        $stream=Open-VerifiedFile $path $Hashes[$name]
        $stream.Dispose()
    }
}
function Copy-NewFile([string]$Source,[string]$Destination,[string]$Expected) {
    $inputStream=Open-VerifiedFile $Source $Expected
    $outputStream=$null
    try {
        $acl=New-PrivateSecurity $false
        $outputStream=[IO.FileStream]::new($Destination,[IO.FileMode]::CreateNew,
            [Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,
            65536,[IO.FileOptions]::WriteThrough,$acl)
        $buffer=[byte[]]::new(65536); $written=0L
        while (($count=$inputStream.Read($buffer,0,$buffer.Length)) -gt 0) {
            $written+=$count
            if ($written -gt $maxFile) { throw 'Copy size exceeded.' }
            $outputStream.Write($buffer,0,$count)
        }
        $outputStream.Flush($true)
        [CfInboundStageNative]::CheckFile($outputStream.SafeFileHandle)
        if ((Stream-Hash $inputStream) -cne $Expected -or (Stream-Hash $outputStream) -cne $Expected) { throw 'Copy changed; partial output preserved for inspection.' }
    } finally {
        if ($null -ne $outputStream) { $outputStream.Dispose() }
        $inputStream.Dispose()
    }
    Assert-PrivateAcl $Destination $false
}

try {
    $source=Normalize-LocalAbsolute $SourceDirectory
    $stage=Normalize-LocalAbsolute $StageDirectory
    if ($source.Equals($stage,[StringComparison]::OrdinalIgnoreCase) -or
        $source.StartsWith($stage+'\',[StringComparison]::OrdinalIgnoreCase) -or
        $stage.StartsWith($source+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Source and stage must be separate non-nested directories.' }
    Hold-Directory $source
    $parent=[IO.Path]::GetDirectoryName($stage)
    Hold-Directory $parent
    Assert-PrivateAcl $parent $true $true
    Assert-KnownTree $source $true $false
    $inventory=Read-Inventory $source $ExpectedInventorySHA256
    Verify-Files $source $inventory.hashes $true
    $exists=Test-Path -LiteralPath $stage
    if ($Mode -eq 'Stage' -and $exists) { throw 'Stage destination already exists; preserved.' }
    if ($Mode -eq 'Check' -and -not $exists) { throw 'Check requires an existing stage.' }
    if ($exists) {
        Assert-KnownTree $stage ($Mode -eq 'Check') $true
        Verify-Files $stage $inventory.hashes ($Mode -eq 'Check')
    }
    if ($Mode -ne 'Check') {
        if (-not $exists) { Create-PrivateDirectory $stage }
        $plugin=Join-Path $stage 'plugin'
        if (-not (Test-Path -LiteralPath $plugin)) { Create-PrivateDirectory $plugin }
        foreach ($name in $allNames) {
            $destination=Join-Path $stage $name
            if (-not (Test-Path -LiteralPath $destination)) { Copy-NewFile (Join-Path $source $name) $destination $inventory.hashes[$name] }
        }
    }
    Assert-KnownTree $stage $true $true
    Verify-Files $stage $inventory.hashes $true
    Assert-KnownTree $source $true $false
    Verify-Files $source $inventory.hashes $true
    Assert-PrivateAcl $parent $true $true
    foreach ($handle in $heldDirectories.Values) { [CfInboundStageNative]::CheckDirectory($handle) }
    @{staged=$true;live_enabled=$false;host_bridge_connected=$false;mode=$Mode;
      source_commit=$inventory.commit;inventory_sha256=$ExpectedInventorySHA256.ToLowerInvariant();
      stage_directory=$stage} | ConvertTo-Json -Compress
} finally {
    foreach ($handle in $heldDirectories.Values) { $handle.Dispose() }
}
