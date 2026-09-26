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
        public static string Identity(string path) {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                                               FileShare.ReadWrite | FileShare.Delete)) {
                FileInfo info;
                if (!GetFileInformationByHandle(stream.SafeFileHandle, out info))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                if (info.Links != 1 || (info.Attributes & 0x400) != 0)
                    throw new IOException("CF_CONFIG_UNSAFE_LINK");
                return info.VolumeSerial.ToString("x8") + ":" + info.IndexHigh.ToString("x8") + info.IndexLow.ToString("x8");
            }
        }
        public static void MovePrepared(string source, string target) {
            // REPLACE_EXISTING | WRITE_THROUGH. Never COPY_ALLOWED, DELAY_UNTIL_REBOOT,
            // or an ACL-error-ignore flag. A cross-volume rename must fail.
            if (!MoveFileExW(source, target, 0x1u | 0x8u))
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
function Set-CfConfigBytesExact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Destination,
        [Parameter(Mandatory=$true)][byte[]]$Bytes,
        [Parameter(Mandatory=$true)][string]$BeforeSha256,
        [Parameter(Mandatory=$true)][string]$AfterSha256,
        [Parameter(Mandatory=$true)][string]$OriginalSddl
    )
    if ($env:OS -ne 'Windows_NT') { throw 'CF_CONFIG_WINDOWS_REQUIRED' }
    if ($BeforeSha256 -cnotmatch '^[0-9a-f]{64}$' -or $AfterSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Bytes.Length -eq 0 -or $Bytes.Length -gt 2097152) { throw 'CF_CONFIG_INVALID_INPUT' }
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $dataHash = ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() } finally { $hash.Dispose() }
    if ($dataHash -cne $AfterSha256) { throw 'CF_CONFIG_CANDIDATE_HASH_MISMATCH' }
    $Destination = [IO.Path]::GetFullPath($Destination)
    Assert-CfConfigPath $Destination
    Initialize-CfConfigNative
    $identityBefore = [CfFileBridge.ConfigNativeV1]::Identity($Destination)
    if ((Get-CfConfigHash $Destination) -cne $BeforeSha256 -or (Get-CfConfigSddl $Destination) -cne $OriginalSddl) {
        throw 'CF_CONFIG_BEFORE_CHANGED'
    }
    $originalAcl = Get-Acl -LiteralPath $Destination -ErrorAction Stop
    $candidate = Join-Path ([IO.Path]::GetDirectoryName($Destination)) ('.cf-config-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $moved = $false
    try {
        # Copy the original security onto a SAME-DIRECTORY staging file. Do not construct
        # a new DACL or merge inherited grants with File.Replace. Only owner/group are aligned.
        [IO.File]::Copy($Destination, $candidate, $false)
        $acl = Get-Acl -LiteralPath $candidate -ErrorAction Stop
        $acl.SetOwner($originalAcl.GetOwner([Security.Principal.SecurityIdentifier]))
        $acl.SetGroup($originalAcl.GetGroup([Security.Principal.SecurityIdentifier]))
        [IO.File]::SetAccessControl($candidate, $acl)
        if ((Get-CfConfigSddl $candidate) -cne $OriginalSddl) { throw 'CF_CONFIG_CANDIDATE_SECURITY_MISMATCH' }
        Assert-CfConfigPath $candidate
        $identityCandidate = [CfFileBridge.ConfigNativeV1]::Identity($candidate)
        if ($identityCandidate.Split(':')[0] -cne $identityBefore.Split(':')[0]) { throw 'CF_CONFIG_DIFFERENT_VOLUME' }
        $stream = [IO.FileStream]::new($candidate, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $stream.SetLength(0)
            $stream.Write($Bytes, 0, $Bytes.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        if ((Get-CfConfigHash $candidate) -cne $AfterSha256 -or (Get-CfConfigSddl $candidate) -cne $OriginalSddl) {
            throw 'CF_CONFIG_STAGED_READBACK_FAILED'
        }
        Assert-CfConfigPath $Destination
        if ([CfFileBridge.ConfigNativeV1]::Identity($Destination) -cne $identityBefore -or
            (Get-CfConfigHash $Destination) -cne $BeforeSha256 -or (Get-CfConfigSddl $Destination) -cne $OriginalSddl) {
            throw 'CF_CONFIG_CONCURRENT_CHANGE'
        }
        [CfFileBridge.ConfigNativeV1]::MovePrepared($candidate, $Destination)
        $moved = $true
        if ((Get-CfConfigHash $Destination) -cne $AfterSha256 -or (Get-CfConfigSddl $Destination) -cne $OriginalSddl -or
            [CfFileBridge.ConfigNativeV1]::Identity($Destination) -cne $identityCandidate -or (Test-Path -LiteralPath $candidate)) {
            throw 'CF_CONFIG_FINAL_READBACK_FAILED'
        }
        return [pscustomobject]@{ hash_verified=$true; owner_group_dacl_exact=$true; method='same-directory-same-volume-rename'; moved=$true }
    } catch {
        # Never automatically overwrite the target again, restore a backup, or restart services.
        Write-Output ('CF_CONFIG_FAILURE_STATE=' + (@{rename_completed=$moved; staging_file=$candidate; staging_exists=(Test-Path -LiteralPath $candidate)} | ConvertTo-Json -Compress))
        throw
    }
}
