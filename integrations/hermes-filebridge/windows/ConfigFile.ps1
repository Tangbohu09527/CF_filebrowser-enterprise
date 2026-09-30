# Windows PowerShell 5.1. Same-volume staged rename, no ReplaceFile ACL merge.
# Caller owns configuration semantics, private backups, process coordination and restart.
# This is not a server-side compare-and-swap or a guarantee against concurrent renames.
Set-StrictMode -Version 2.0

function Initialize-CfConfigNative {
    if ($null -ne ('CfFileBridge.ConfigNativeV1' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace CfFileBridge {
    public static class ConfigNativeV1 {
        [StructLayout(LayoutKind.Sequential)]
        private struct FileInfo {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle h, out FileInfo info);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool MoveFileExW(string source, string target, uint flags);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileSecurityW(string path, uint information, byte[] descriptor);
        public static void SetLegacyDacl(string path, byte[] descriptor) {
            // SetSecurityInfo (used by .NET) can add AUTO_INHERITED to an otherwise
            // identical DACL. Use the legacy setter only on our candidate; the caller
            // still requires the complete owner/group/DACL descriptor to match exactly.
            if (!SetFileSecurityW(path, 0x4u, descriptor))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        public static string Identity(string path) {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                                               FileShare.ReadWrite | FileShare.Delete)) {
                return IdentityHandle(stream.SafeFileHandle);
            }
        }
        public static string IdentityHandle(SafeFileHandle handle) {
                FileInfo info;
                if (!GetFileInformationByHandle(handle, out info))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                if (info.Links != 1 || (info.Attributes & 0x400) != 0)
                    throw new IOException("CF_CONFIG_UNSAFE_LINK");
                return info.VolumeSerial.ToString("x8") + ":" + info.IndexHigh.ToString("x8") + info.IndexLow.ToString("x8");
        }
        public static void MovePrepared(string source, string target, bool replace) {
            // REPLACE_EXISTING | WRITE_THROUGH. Never COPY_ALLOWED, DELAY_UNTIL_REBOOT,
            // or an ACL-error-ignore flag. A cross-volume rename must fail.
            if (!MoveFileExW(source, target, (replace ? 0x1u : 0u) | 0x8u))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}
'@
}
function Assert-CfConfigPath([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\')) { throw 'CF_CONFIG_LOCAL_ABSOLUTE_REQUIRED' }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -gt 2097152) { throw 'CF_CONFIG_FILE_TYPE_OR_SIZE' }
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'CF_CONFIG_REPARSE_REFUSED' }
        if ($item -is [IO.FileInfo]) { $item = $item.Directory } else { $item = $item.Parent }
    }
}
function Get-CfConfigHash([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}
function Get-CfConfigSddl([string]$Path) {
    $sections = [Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
    return (Get-Acl -LiteralPath $Path -ErrorAction Stop).GetSecurityDescriptorSddlForm($sections)
}
function Assert-CfConfigParent([string]$Path) {
    $node=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($Path)) -Force -ErrorAction Stop
    if (-not $node.PSIsContainer) { throw 'CF_CONFIG_FILE_TYPE_OR_SIZE' }
    while ($null -ne $node) {
        if ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'CF_CONFIG_REPARSE_REFUSED' }
        $node=$node.Parent
    }
}
function Assert-CfConfigLegacyResidue([string]$Path, [string]$Target) {
    # Observation only. This does not prove that we own a legacy candidate.
    try {
        Initialize-CfConfigNative
        Assert-CfConfigPath $Path; Assert-CfConfigPath $Target
        if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path)) -ine [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Target)) -or
            [IO.Path]::GetFileName($Path) -cnotmatch '^\.cf-config-[0-9a-f]{32}\.tmp$') { throw 'mismatch' }
        $null=[CfFileBridge.ConfigNativeV1]::Identity($Path);$null=[CfFileBridge.ConfigNativeV1]::Identity($Target)
        # The caller separately pins legacy bytes to its approved old inventory.
        # Target bytes may already be new after a completed transaction.
        $source=[Security.AccessControl.RawSecurityDescriptor]::new((Get-CfConfigSddl $Target))
        $residue=[Security.AccessControl.RawSecurityDescriptor]::new((Get-CfConfigSddl $Path))
        if ($source.Owner.Value -cne $residue.Owner.Value -or $source.Group.Value -cne $residue.Group.Value -or
            ([int]$source.ControlFlags -bxor [int]$residue.ControlFlags) -ne 1024 -or
            ([int]$source.ControlFlags -band 1024) -ne 0 -or
            $null -eq $source.DiscretionaryAcl -or $null -eq $residue.DiscretionaryAcl) { throw 'mismatch' }
        $left=New-Object byte[] $source.DiscretionaryAcl.BinaryLength
        $right=New-Object byte[] $residue.DiscretionaryAcl.BinaryLength
        $source.DiscretionaryAcl.GetBinaryForm($left,0);$residue.DiscretionaryAcl.GetBinaryForm($right,0)
        if ([Convert]::ToBase64String($left) -cne [Convert]::ToBase64String($right)) { throw 'mismatch' }
        return [pscustomobject]@{compatible=$true;owned=$false;candidate_name=[IO.Path]::GetFileName($Path)}
    } catch { throw [InvalidOperationException]::new('CF_CONFIG_LEGACY_RESIDUE_MISMATCH') }
}
function Assert-CfConfigJournalDirectory([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\')) { throw 'CF_CONFIG_JOURNAL_INVALID' }
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer) { throw 'CF_CONFIG_JOURNAL_INVALID' }
    $node=$item
    while ($null -ne $node) {
        if ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'CF_CONFIG_JOURNAL_INVALID' }
        $node=$node.Parent
    }
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    $allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
    if (-not $acl.AreAccessRulesProtected -or -not $acl.AreAccessRulesCanonical -or
        $allowed -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw 'CF_CONFIG_JOURNAL_INVALID' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($allowed -notcontains $rule.IdentityReference.Value -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw 'CF_CONFIG_JOURNAL_INVALID'
        }
    }
}
function Get-CfConfigJournalPaths([string]$TransactionDirectory,[string]$TargetName) {
    if ($TargetName -cnotmatch '^(config\.yaml|plugin/(__init__\.py|plugin\.yaml|inbound(_control|_directory|_host|_content)?\.py))$') {
        throw 'CF_CONFIG_JOURNAL_INVALID'
    }
    $h=[Security.Cryptography.SHA256]::Create()
    try { $key=([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($TargetName)))).Replace('-','').ToLowerInvariant() }
    finally { $h.Dispose() }
    return @((Join-Path $TransactionDirectory ($key+'.intent.json')),(Join-Path $TransactionDirectory ($key+'.owned.json')))
}
function Read-CfConfigJournal([string]$Path,[string[]]$Keys) {
    Assert-CfConfigPath $Path
    $null=[CfFileBridge.ConfigNativeV1]::Identity($Path)
    $acl=Get-Acl -LiteralPath $Path
    $allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
    if (-not $acl.AreAccessRulesCanonical -or $allowed -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw 'CF_CONFIG_JOURNAL_INVALID' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($allowed -notcontains $rule.IdentityReference.Value -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { throw 'CF_CONFIG_JOURNAL_INVALID' }
    }
    $stream=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($stream.Length -gt 16384) { throw 'CF_CONFIG_JOURNAL_INVALID' }
        $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true))
        try { $record=ConvertFrom-Json -InputObject $reader.ReadToEnd() -ErrorAction Stop } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
    if ($null -eq $record -or (@($record.PSObject.Properties.Name | Sort-Object) -join '|') -cne (@($Keys | Sort-Object) -join '|')) { throw 'CF_CONFIG_JOURNAL_INVALID' }
    return $record
}
function Write-CfConfigJournal([string]$Path,$Record) {
    $data=[Text.UTF8Encoding]::new($false).GetBytes(($Record | ConvertTo-Json -Compress))
    if ($data.Length -gt 16384) { throw 'CF_CONFIG_JOURNAL_INVALID' }
    $stream=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try { $stream.Write($data,0,$data.Length);$stream.Flush($true) } finally { $stream.Dispose() }
}
function Assert-CfConfigTransactionJournal {
    [CmdletBinding()]
    param([string]$TransactionDirectory,[string]$TargetName,[string]$Destination,
        [AllowEmptyString()][string]$BeforeSha256,[string]$AfterSha256,[string]$OriginalSddl,[switch]$AllowCreate)
    try {
        Initialize-CfConfigNative
        $paths=Get-CfConfigJournalPaths $TransactionDirectory $TargetName
        $result=[pscustomobject]@{present=$false;candidate_name='';candidate_exists=$false;rename_completed=$false;owned_candidate=$false;journal_names=@();source_identity='';candidate_identity=''}
        if (-not (Test-Path -LiteralPath $TransactionDirectory)) { return $result }
        Assert-CfConfigJournalDirectory $TransactionDirectory
        if (-not (Test-Path -LiteralPath $paths[0])) {
            if (Test-Path -LiteralPath $paths[1]) { throw 'CF_CONFIG_JOURNAL_INVALID' }
            return $result
        }
        $intent=Read-CfConfigJournal $paths[0] @('version','target','destination','before','after','security','source_identity','candidate','allow_create')
        if ($intent.version -ne 1 -or $intent.target -cne $TargetName -or $intent.destination -cne [IO.Path]::GetFullPath($Destination) -or
            $intent.before -cne $BeforeSha256 -or $intent.after -cne $AfterSha256 -or $intent.security -cne $OriginalSddl -or
            $intent.allow_create -isnot [bool] -or $intent.allow_create -ne [bool]$AllowCreate -or
            $intent.candidate -cnotmatch '^\.cf-config-[0-9a-f]{32}\.tmp$' -or
            ((-not $AllowCreate) -and $intent.source_identity -cnotmatch '^[0-9a-f]{8}:[0-9a-f]{16}$') -or
            ($AllowCreate -and $intent.source_identity -cne 'absent')) { throw 'CF_CONFIG_JOURNAL_CONFLICT' }
        $candidate=Join-Path ([IO.Path]::GetDirectoryName($Destination)) $intent.candidate
        $result.present=$true;$result.candidate_name=$intent.candidate;$result.source_identity=$intent.source_identity
        $result.journal_names=@([IO.Path]::GetFileName($paths[0]));$result.candidate_exists=Test-Path -LiteralPath $candidate
        if (-not (Test-Path -LiteralPath $paths[1])) {
            if ($result.candidate_exists) { throw 'CF_CONFIG_UNOWNED_CANDIDATE' }
            return $result
        }
        $owned=Read-CfConfigJournal $paths[1] @('version','intent_sha256','candidate_identity')
        if ($owned.version -ne 1 -or $owned.intent_sha256 -cne (Get-CfConfigHash $paths[0]) -or
            $owned.candidate_identity -cnotmatch '^[0-9a-f]{8}:[0-9a-f]{16}$') { throw 'CF_CONFIG_JOURNAL_INVALID' }
        $result.journal_names+=@([IO.Path]::GetFileName($paths[1]));$result.candidate_identity=$owned.candidate_identity
        if ($result.candidate_exists) {
            Assert-CfConfigPath $candidate
            if ([CfFileBridge.ConfigNativeV1]::Identity($candidate) -cne $owned.candidate_identity -or
                (Get-CfConfigSddl $candidate) -cne $OriginalSddl) { throw 'CF_CONFIG_JOURNAL_CONFLICT' }
            $result.owned_candidate=$true
        } else {
            Assert-CfConfigPath $Destination
            if ([CfFileBridge.ConfigNativeV1]::Identity($Destination) -cne $owned.candidate_identity -or
                (Get-CfConfigHash $Destination) -cne $AfterSha256 -or (Get-CfConfigSddl $Destination) -cne $OriginalSddl) { throw 'CF_CONFIG_JOURNAL_CONFLICT' }
            $result.rename_completed=$true
        }
        return $result
    } catch {
        $message='CF_CONFIG_JOURNAL_INVALID'
        if ($_.Exception.Message -cin @('CF_CONFIG_JOURNAL_CONFLICT','CF_CONFIG_UNOWNED_CANDIDATE')) { $message=$_.Exception.Message }
        throw [InvalidOperationException]::new($message)
    }
}
function Set-CfConfigBytesExact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Destination,
        [Parameter(Mandatory=$true)][byte[]]$Bytes,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$BeforeSha256,
        [Parameter(Mandatory=$true)][string]$AfterSha256,
        [Parameter(Mandatory=$true)][string]$OriginalSddl,
        [string]$TransactionDirectory='', [string]$TargetName='config.yaml', [switch]$AllowCreate
    )
    $stage='input_validate';$candidate=$null;$moved=$false
    try {
    if ($env:OS -ne 'Windows_NT') { throw 'CF_CONFIG_WINDOWS_REQUIRED' }
    if (((-not $AllowCreate) -and $BeforeSha256 -cnotmatch '^[0-9a-f]{64}$') -or
        ($AllowCreate -and $BeforeSha256 -cne '') -or $AfterSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Bytes.Length -eq 0 -or $Bytes.Length -gt 2097152) { throw 'CF_CONFIG_INVALID_INPUT' }
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $dataHash = ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() } finally { $hash.Dispose() }
    if ($dataHash -cne $AfterSha256) { throw 'CF_CONFIG_CANDIDATE_HASH_MISMATCH' }
    if (-not [IO.Path]::IsPathRooted($Destination) -or $Destination.StartsWith('\\')) { throw 'CF_CONFIG_LOCAL_ABSOLUTE_REQUIRED' }
    $Destination = [IO.Path]::GetFullPath($Destination)
    Initialize-CfConfigNative
    $journal=$null;$paths=$null
    if ($TransactionDirectory) {
        $stage='journal_validate'
        Assert-CfConfigJournalDirectory $TransactionDirectory
        $paths=Get-CfConfigJournalPaths $TransactionDirectory $TargetName
        $journal=Assert-CfConfigTransactionJournal -TransactionDirectory $TransactionDirectory -TargetName $TargetName -Destination $Destination -BeforeSha256 $BeforeSha256 -AfterSha256 $AfterSha256 -OriginalSddl $OriginalSddl -AllowCreate:$AllowCreate
        if ($journal.rename_completed) {
            return [pscustomobject]@{hash_verified=$true;owner_group_dacl_exact=$true;method='same-directory-same-volume-rename';moved=$true;resumed=$true}
        }
    }
    $stage='source_validate'
    Assert-CfConfigParent $Destination
    if ($AllowCreate) {
        if (Test-Path -LiteralPath $Destination) { throw 'CF_CONFIG_TARGET_EXISTS' }
        $identityBefore='absent'
        $originalAcl=[Security.AccessControl.FileSecurity]::new()
        $originalAcl.SetSecurityDescriptorSddlForm($OriginalSddl)
    } else {
        Assert-CfConfigPath $Destination
        $identityBefore = [CfFileBridge.ConfigNativeV1]::Identity($Destination)
        if ((Get-CfConfigHash $Destination) -cne $BeforeSha256 -or (Get-CfConfigSddl $Destination) -cne $OriginalSddl) { throw 'CF_CONFIG_BEFORE_CHANGED' }
        $originalAcl = Get-Acl -LiteralPath $Destination -ErrorAction Stop
    }
    if ($null -ne $journal -and $journal.present) {
        if ($journal.source_identity -cne $identityBefore) { throw 'CF_CONFIG_CONCURRENT_CHANGE' }
        $candidate=Join-Path ([IO.Path]::GetDirectoryName($Destination)) $journal.candidate_name
    } else {
        $candidate=Join-Path ([IO.Path]::GetDirectoryName($Destination)) ('.cf-config-'+[Guid]::NewGuid().ToString('N')+'.tmp')
        if ($TransactionDirectory) {
            $stage='journal_create'
            Write-CfConfigJournal $paths[0] ([ordered]@{version=1;target=$TargetName;destination=$Destination;before=$BeforeSha256;after=$AfterSha256;security=$OriginalSddl;source_identity=$identityBefore;candidate=[IO.Path]::GetFileName($candidate);allow_create=[bool]$AllowCreate})
        }
    }
    if ($null -eq $journal -or -not $journal.owned_candidate) {
        $stage='candidate_create'
        # Copy the original security onto a SAME-DIRECTORY staging file. Do not construct
        # a new grant policy or merge inherited grants with File.Replace. Reuse exact source security.
        if ($AllowCreate) {
            $stream=[IO.FileStream]::new($candidate,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough,$originalAcl)
            $stream.Dispose()
        } else { [IO.File]::Copy($Destination, $candidate, $false) }
        $stage='candidate_security'
        $acl = Get-Acl -LiteralPath $candidate -ErrorAction Stop
        $acl.SetOwner($originalAcl.GetOwner([Security.Principal.SecurityIdentifier]))
        $acl.SetGroup($originalAcl.GetGroup([Security.Principal.SecurityIdentifier]))
        [IO.File]::SetAccessControl($candidate, $acl)
        if ((Get-CfConfigSddl $candidate) -cne $OriginalSddl) {
            # CopyFile can re-inherit security, especially for a protected original.
            # Apply the ORIGINAL descriptor to the staging file only; require exact readback.
            $exact = [Security.AccessControl.FileSecurity]::new()
            $parts = [Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
            $exact.SetSecurityDescriptorSddlForm($OriginalSddl, $parts)
            [IO.File]::SetAccessControl($candidate, $exact)
            if ((Get-CfConfigSddl $candidate) -cne $OriginalSddl) {
                [CfFileBridge.ConfigNativeV1]::SetLegacyDacl($candidate, $exact.GetSecurityDescriptorBinaryForm())
            }
            if ((Get-CfConfigSddl $candidate) -cne $OriginalSddl) { throw 'CF_CONFIG_CANDIDATE_SECURITY_MISMATCH' }
        }
        $identityCandidate=[CfFileBridge.ConfigNativeV1]::Identity($candidate)
        if ($TransactionDirectory) {
            $stage='journal_create'
            Write-CfConfigJournal $paths[1] ([ordered]@{version=1;intent_sha256=(Get-CfConfigHash $paths[0]);candidate_identity=$identityCandidate})
        }
    } else { $stage='journal_recover';$identityCandidate=$journal.candidate_identity }
        Assert-CfConfigPath $candidate
        if ([CfFileBridge.ConfigNativeV1]::Identity($candidate) -cne $identityCandidate) { throw 'CF_CONFIG_JOURNAL_CONFLICT' }
        if (-not $AllowCreate -and $identityCandidate.Split(':')[0] -cne $identityBefore.Split(':')[0]) { throw 'CF_CONFIG_DIFFERENT_VOLUME' }
        $stage='candidate_write'
        $stream = [IO.FileStream]::new($candidate, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            if ([CfFileBridge.ConfigNativeV1]::IdentityHandle($stream.SafeFileHandle) -cne $identityCandidate) { throw 'CF_CONFIG_JOURNAL_CONFLICT' }
            $stream.SetLength(0)
            $stream.Write($Bytes, 0, $Bytes.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        $stage='candidate_verify'
        if ([CfFileBridge.ConfigNativeV1]::Identity($candidate) -cne $identityCandidate -or
            (Get-CfConfigHash $candidate) -cne $AfterSha256 -or (Get-CfConfigSddl $candidate) -cne $OriginalSddl) {
            throw 'CF_CONFIG_STAGED_READBACK_FAILED'
        }
        $stage='target_recheck'
        if ($AllowCreate) {
            if (Test-Path -LiteralPath $Destination) { throw 'CF_CONFIG_TARGET_EXISTS' }
        } else {
            Assert-CfConfigPath $Destination
            if ([CfFileBridge.ConfigNativeV1]::Identity($Destination) -cne $identityBefore -or
                (Get-CfConfigHash $Destination) -cne $BeforeSha256 -or (Get-CfConfigSddl $Destination) -cne $OriginalSddl) { throw 'CF_CONFIG_CONCURRENT_CHANGE' }
        }
        $stage='rename'
        [CfFileBridge.ConfigNativeV1]::MovePrepared($candidate, $Destination, (-not $AllowCreate))
        $moved = $true
        $stage='final_verify'
        if ((Get-CfConfigHash $Destination) -cne $AfterSha256 -or (Get-CfConfigSddl $Destination) -cne $OriginalSddl -or
            [CfFileBridge.ConfigNativeV1]::Identity($Destination) -cne $identityCandidate -or (Test-Path -LiteralPath $candidate)) {
            throw 'CF_CONFIG_FINAL_READBACK_FAILED'
        }
        return [pscustomobject]@{ hash_verified=$true; owner_group_dacl_exact=$true; method='same-directory-same-volume-rename'; moved=$true }
    } catch {
        # Never automatically overwrite the target again, restore a backup, or restart services.
        $codes=@('CF_CONFIG_WINDOWS_REQUIRED','CF_CONFIG_INVALID_INPUT','CF_CONFIG_CANDIDATE_HASH_MISMATCH','CF_CONFIG_LOCAL_ABSOLUTE_REQUIRED',
            'CF_CONFIG_FILE_TYPE_OR_SIZE','CF_CONFIG_REPARSE_REFUSED','CF_CONFIG_UNSAFE_LINK','CF_CONFIG_BEFORE_CHANGED',
            'CF_CONFIG_CANDIDATE_SECURITY_MISMATCH','CF_CONFIG_DIFFERENT_VOLUME','CF_CONFIG_STAGED_READBACK_FAILED',
            'CF_CONFIG_CONCURRENT_CHANGE','CF_CONFIG_FINAL_READBACK_FAILED','CF_CONFIG_JOURNAL_INVALID','CF_CONFIG_UNOWNED_CANDIDATE',
            'CF_CONFIG_JOURNAL_CONFLICT','CF_CONFIG_TARGET_EXISTS')
        $code='CF_CONFIG_OPERATION_FAILED';$errorObject=$_.Exception
        while ($null -ne $errorObject) { if ($errorObject.Message -cin $codes) { $code=$errorObject.Message;break };$errorObject=$errorObject.InnerException }
        $safe=[InvalidOperationException]::new($code)
        $safe.Data['cf_stage']=$stage;$safe.Data['cf_rename_completed']=[bool]$moved
        if ($null -eq $candidate) { $safe.Data['cf_staging_exists']=$false }
        else { try { $safe.Data['cf_staging_exists']=[bool](Test-Path -LiteralPath $candidate -ErrorAction Stop) } catch { } }
        throw $safe
    }
}
