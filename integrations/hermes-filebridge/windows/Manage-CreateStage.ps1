# Coordinates the pinned side-by-side staging engine. No live Hermes edits or remote writes.
# Recovery accepts only the exact CPython Windows mkdir(0700) ACL, after byte verification.
[CmdletBinding()]
param(
    [ValidateSet('Stage','Recover','SelfTest')][string]$Mode='Recover',
    [string]$StageScript='',
    [string]$PythonPath='',
    [string]$ArtifactPath=(Join-Path $env:USERPROFILE 'Downloads\filebridge-client-windows-28a4481f.zip'),
    [string]$OriginalInstallDir=(Join-Path $env:USERPROFILE 'CF-FileBridge\client-04c7e717'),
    [string]$InstallDir=(Join-Path $env:USERPROFILE 'CF-FileBridge\client-28a4481f'),
    [string]$HermesHome=(Join-Path $env:LOCALAPPDATA 'hermes')
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$utf8=[Text.UTF8Encoding]::new($false)
$phase='preflight';$record=$null;$exitCode=1
$oldEncoding=$OutputEncoding
$oldConsole=[Console]::OutputEncoding
$dirs=@('bin','plugin','audit','evidence','create-state')

function Assert-Path([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\')) { throw 'LOCAL_ABSOLUTE_PATH_REQUIRED' }
    $item=Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'REPARSE_POINT_REFUSED' }
        if ($item -is [IO.FileInfo]) { $item=$item.Directory } else { $item=$item.Parent }
    }
}
function Get-AclShape([string]$Path) {
    Assert-Path $Path
    $item=Get-Item -LiteralPath $Path -Force
    $acl=Get-Acl -LiteralPath $Path
    $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {
        [pscustomobject]@{sid=$_.IdentityReference.Value; rights=[int]$_.FileSystemRights;
            type=[int]$_.AccessControlType; inherit=[int]$_.InheritanceFlags;
            propagate=[int]$_.PropagationFlags; inherited=[bool]$_.IsInherited}
    })
    $sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
    return [pscustomobject]@{path=$Path;directory=[bool]$item.PSIsContainer;
        owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;
        protected=[bool]$acl.AreAccessRulesProtected;rules=$rules;
        sddl=$acl.GetSecurityDescriptorSddlForm($sections)}
}
function Is-Private($Shape) {
    if ($Shape.owner -ne $script:sid -and $Shape.owner -ne $script:defaultOwner) { return $false }
    $seen=@{}
    foreach ($r in $Shape.rules) {
        if (@($script:sid,'S-1-5-18') -notcontains $r.sid -or $r.type -ne 0 -or $r.rights -ne 2032127) { return $false }
        if (($r.propagate -band 2) -eq 0) { $seen[$r.sid]=$true }
    }
    return ($seen.ContainsKey($script:sid) -and $seen.ContainsKey('S-1-5-18'))
}
function Is-Python700($Shape) {
    if ($Shape.owner -ne $script:sid -and -not ($Shape.owner -eq $script:defaultOwner -and $Shape.owner -eq 'S-1-5-32-544')) { return $false }
    if ($Shape.rules.Count -ne 3 -or $Shape.protected -ne $Shape.directory) { return $false }
    $seen=@{}
    foreach ($r in $Shape.rules) {
        if (@('S-1-5-18','S-1-5-32-544','S-1-3-4') -notcontains $r.sid -or $seen.ContainsKey($r.sid) -or
            $r.type -ne 0 -or $r.rights -ne 2032127 -or $r.propagate -ne 0) { return $false }
        if ($Shape.directory) { if ($r.inherit -ne 3 -or $r.inherited) { return $false } }
        else { if ($r.inherit -ne 0 -or -not $r.inherited) { return $false } }
        $seen[$r.sid]=$true
    }
    return $true
}
function Set-Private([string]$Path,[bool]$NewDirectory=$false) {
    if ($NewDirectory) {
        if (Test-Path -LiteralPath $Path) { throw 'EXISTING_DIRECTORY_REFUSED' }
        Assert-Path (Split-Path -Parent $Path)
        $isDir=$true;$group=$null
    } else {
        $shape=Get-AclShape $Path
        if (-not (Is-Private $shape) -and -not (Is-Python700 $shape)) { throw 'UNEXPECTED_ACL_NO_REPAIR' }
        $isDir=$shape.directory
        $group=(Get-Acl -LiteralPath $Path).GetGroup([Security.Principal.SecurityIdentifier])
    }
    if ($isDir) { $acl=[Security.AccessControl.DirectorySecurity]::new() }
    else { $acl=[Security.AccessControl.FileSecurity]::new() }
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($script:sid))
    if ($null -ne $group) { $acl.SetGroup($group) }
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($id in @($script:sid,'S-1-5-18')) {
        $inherit=[Security.AccessControl.InheritanceFlags]::None
        if ($isDir) { $inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit }
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($id),[Security.AccessControl.FileSystemRights]::FullControl,
            $inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    if ($NewDirectory) { [IO.Directory]::CreateDirectory($Path,$acl) | Out-Null }
    elseif ($isDir) { [IO.Directory]::SetAccessControl($Path,$acl) }
    else { [IO.File]::SetAccessControl($Path,$acl) }
    $after=Get-AclShape $Path
    if (-not (Is-Private $after) -or $after.owner -ne $script:sid -or -not $after.protected) { throw 'PRIVATE_ACL_READBACK_FAILED' }
}
function Get-Nodes([string]$Root) {
    $stack=[Collections.Generic.Stack[string]]::new();$stack.Push($Root)
    $result=[Collections.Generic.List[object]]::new()
    while ($stack.Count -gt 0) {
        $name=$stack.Pop();Assert-Path $name
        $item=Get-Item -LiteralPath $name -Force
        $result.Add($item)
        if ($result.Count -gt 64) { throw 'UNEXPECTED_TREE_SIZE' }
        if ($item.PSIsContainer) { foreach ($c in @(Get-ChildItem -LiteralPath $name -Force)) { $stack.Push($c.FullName) } }
    }
    return $result.ToArray()
}
function Get-FileHashes($Nodes) {
    $hashes=@{}
    foreach ($n in $Nodes) { if (-not $n.PSIsContainer) { $hashes[$n.FullName]=(Get-FileHash -LiteralPath $n.FullName -Algorithm SHA256).Hash } }
    return $hashes
}
function Test-NativePython {
    $tmp=Join-Path ([IO.Path]::GetTempPath()) ('cf-py700-'+[Guid]::NewGuid().ToString('N'))
    Set-Private $tmp $true
    $child=Join-Path $tmp 'python700';$file=Join-Path $child 'dummy.txt'
    & $PythonPath -I -S -B -c "from pathlib import Path;import sys;p=Path(sys.argv[1]);p.mkdir(mode=0o700);(p/'dummy.txt').write_bytes(b'non-secret fixture')" $child
    if ($LASTEXITCODE -ne 0) { throw 'PYTHON_REPRODUCER_FAILED' }
    $shape=Get-AclShape $child
    Write-Output ('PYTHON700_NATIVE_ACL='+($shape | ConvertTo-Json -Depth 6 -Compress))
    if ((Is-Private $shape) -or -not (Is-Python700 $shape) -or -not (Is-Python700 (Get-AclShape $file))) { throw 'PYTHON700_SHAPE_NOT_REPRODUCED' }
    $hash=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    # Children first avoids an uninspected implicit inheritance transition.
    Set-Private $file
    Set-Private $child
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $hash) { throw 'CONTENT_CHANGED' }
    # Cross-language regression: precreated private directories skip Python's 0700 branch.
    $fixed=Join-Path $tmp 'fixed';Set-Private $fixed $true
    foreach ($d in $dirs) { Set-Private (Join-Path $fixed $d) $true }
    & $PythonPath -I -S -B -c "from pathlib import Path;import sys;p=Path(sys.argv[1]);[(q.mkdir(mode=0o700) if not q.exists() else None,(q/'dummy.txt').write_bytes(b'unchanged')) for q in (p/n for n in ('bin','plugin','audit','evidence','create-state'))]" $fixed
    if ($LASTEXITCODE -ne 0) { throw 'CROSS_LANGUAGE_STAGE_FAILED' }
    foreach ($n in @(Get-Nodes $fixed)) { if (-not (Is-Private (Get-AclShape $n.FullName))) { throw 'PRECREATED_PRIVATE_ACL_NOT_RETAINED' } }
    $acl=Get-Acl -LiteralPath $file
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow))
    [IO.File]::SetAccessControl($file,$acl)
    if ((Is-Private (Get-AclShape $file)) -or (Is-Python700 (Get-AclShape $file))) { throw 'UNEXPECTED_TRUSTEE_ACCEPTED' }
    $denied=$false;try { Set-Private $file } catch { $denied=$true }
    if (-not $denied) { throw 'UNEXPECTED_ACL_REPAIRED' }
    # Delete only the exact known non-secret fixture paths, never production paths.
    Remove-Item -LiteralPath $file;Remove-Item -LiteralPath $child
    foreach ($d in $dirs) { Remove-Item -LiteralPath (Join-Path $fixed ($d+'\dummy.txt'));Remove-Item -LiteralPath (Join-Path $fixed $d) }
    Remove-Item -LiteralPath $fixed;Remove-Item -LiteralPath $tmp
    Write-Output 'PYTHON700_REPRODUCED=PASS'
    Write-Output 'CROSS_LANGUAGE_PRIVATE_STAGE=PASS'
    Write-Output 'UNKNOWN_ACL_REFUSED=PASS'
}
try {
    if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop') { throw 'WINDOWS_POWERSHELL_REQUIRED' }
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $script:sid=$identity.User.Value;$script:defaultOwner=$identity.Owner.Value
    $OutputEncoding=$utf8;[Console]::OutputEncoding=$utf8
    if (-not $PythonPath) {
        if ($Mode -eq 'SelfTest') { $PythonPath=(Get-Command python.exe -CommandType Application | Select-Object -First 1).Source }
        else { $PythonPath=Join-Path $HermesHome 'hermes-agent\venv\Scripts\python.exe' }
    }
    Assert-Path $PythonPath
    if ($Mode -eq 'SelfTest') { Test-NativePython;$exitCode=0 }
    else {
        if (-not $StageScript) {
            $StageScript=Join-Path $PSScriptRoot 'Stage-CreateClient.ps1'
            if (-not (Test-Path -LiteralPath $StageScript)) { $StageScript=Join-Path $env:USERPROFILE 'Downloads\cf-stage-filebridge-create-client.ps1' }
        }
        Assert-Path $StageScript
        # Normalize CRLF for the fixed-source comparison only, never rewrite the engine.
        $source=[IO.File]::ReadAllText($StageScript).Replace("`r`n","`n")
        $sha=[Security.Cryptography.SHA256]::Create()
        try { $digest=([BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes($source)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
        if ($digest -ne '70dfb44a2273ec0264b449f0bb47220eb475c6ecf85a912da494a171d594a1ee') { throw 'PINNED_STAGE_ENGINE_CHANGED' }
        $InstallDir=[IO.Path]::GetFullPath($InstallDir);$OriginalInstallDir=[IO.Path]::GetFullPath($OriginalInstallDir)
        if ($InstallDir -eq $OriginalInstallDir -or (Split-Path -Parent $InstallDir) -ne (Split-Path -Parent $OriginalInstallDir)) { throw 'SIBLING_RELEASE_REQUIRED' }
        if ($Mode -eq 'Stage') {
            $phase='create-explicit-private-directories'
            Set-Private $InstallDir $true
            foreach ($d in $dirs) { Set-Private (Join-Path $InstallDir $d) $true }
            $engineMode='Resume'
        } else {
            $phase='verify-complete-preprobe-checkpoint'
            $rootShape=Get-AclShape $InstallDir
            if (-not (Is-Private $rootShape) -or $rootShape.owner -ne $script:sid -or -not $rootShape.protected) { throw 'ROOT_NOT_PRIVATE_NO_REPAIR' }
            $check=@'
import argparse, hashlib, re, sys
from pathlib import Path
from types import SimpleNamespace
p=argparse.ArgumentParser()
for n in ('engine','old','new','home','artifact'):p.add_argument('--'+n,type=Path,required=True)
p.add_argument('--sid',required=True)
a=p.parse_args()
try:
    raw=a.engine.read_bytes().replace(b'\r\n',b'\n')
    assert hashlib.sha256(raw).hexdigest()=='70dfb44a2273ec0264b449f0bb47220eb475c6ecf85a912da494a171d594a1ee'
    core=re.search(rb"\$core=@'\n(.*?)\n'@",raw,re.S).group(1)
    ns={'__name__':'_verified_stage_checkpoint','__file__':str(a.engine)}
    exec(compile(core,'<pinned-stage-core>','exec'),ns)
    read,need=ns['read'],ns['need']
    need(read(a.new/'stage-core.py',100000).replace(b'\r\n',b'\n')==core,'STAGED_DRIVER_CHANGED')
    cfg,baseline=ns['old_baseline'](a.old,a.home,a.sid)
    blobs,plugins=ns['check_artifact'](read(a.artifact,64*1024**2))
    files=ns['expected_files'](a.old,a.new,cfg,blobs,plugins)
    ns['validate_new_tree'](a.new,files)
    need(ns['load'](read(a.new/'stage-manifest.json'))==ns['inventory'](a,baseline,files),'MANIFEST_CHANGED')
    for name,value in files.items():need(read(a.new/name,max(len(value),65536))==value,'STAGED_BYTES_CHANGED')
    actual={f.relative_to(a.new).as_posix() for f in a.new.rglob('*') if f.is_file()}
    need(actual==set(files)|{'stage-core.py','stage-manifest.json'},'NOT_COMPLETE_PREPROBE_CHECKPOINT')
    need({f.relative_to(a.new).as_posix() for f in a.new.iterdir() if f.is_dir()}==set(ns['DIRS']),'DIRECTORIES_CHANGED')
    print('COMPLETE_PREPROBE_CHECKPOINT=PASS',flush=True)
except Exception as exc:
    print('CHECKPOINT_ERROR='+type(exc).__name__,flush=True);sys.exit(1)
'@
            $check | & $PythonPath -I -S -u -B - --engine $StageScript --old $OriginalInstallDir --new $InstallDir --home $HermesHome --artifact $ArtifactPath --sid $script:sid
            if ($LASTEXITCODE -ne 0) { throw 'CHECKPOINT_REFUSED_NO_ACL_CHANGE' }
            $nodes=@(Get-Nodes $InstallDir);$before=@();$affected=0
            foreach ($n in $nodes) {
                $s=Get-AclShape $n.FullName
                if (-not (Is-Private $s) -and -not (Is-Python700 $s)) {
                    Write-Output ('UNEXPECTED_ACL='+($s | ConvertTo-Json -Depth 6 -Compress));throw 'UNEXPECTED_ACL_NO_REPAIR'
                }
                if (Is-Python700 $s) { $affected++ }
                $before+= $s
            }
            Write-Output ('KNOWN_PYTHON700_NODES='+$affected)
            $hashes=Get-FileHashes $nodes
            $record=Join-Path (Split-Path -Parent $InstallDir) ('acl-recovery-28a4481f-'+[Guid]::NewGuid().ToString('N'))
            Set-Private $record $true
            $evidence=Join-Path $record 'before.json'
            [IO.File]::WriteAllText($evidence,(@{acl=$before;hashes=$hashes} | ConvertTo-Json -Depth 8),$utf8)
            Set-Private $evidence
            Write-Output ('ACL_RECOVERY_RECORD='+$record)
            $phase='narrow-only-reviewed-new-release-acl'
            # Snapshot and classify ALL nodes first; repair children first.
            foreach ($n in @($nodes | Sort-Object { $_.FullName.Length } -Descending)) {
                if ($n.FullName -eq $InstallDir) { continue }
                Set-Private $n.FullName
            }
            $afterHashes=Get-FileHashes @(Get-Nodes $InstallDir)
            if ($afterHashes.Count -ne $hashes.Count) { throw 'CONTENT_TREE_CHANGED_DURING_REPAIR' }
            foreach ($key in $hashes.Keys) { if ($afterHashes[$key] -ne $hashes[$key]) { throw 'CONTENT_CHANGED_DURING_REPAIR' } }
            foreach ($n in @(Get-Nodes $InstallDir)) {
                $s=Get-AclShape $n.FullName
                if (-not (Is-Private $s) -or $s.owner -ne $script:sid) { throw 'ACL_FINAL_CHECK_FAILED' }
            }
            Write-Output 'NEW_RELEASE_ACL_RECOVERY=PASS'
            Write-Output 'EXISTING_STAGE_BYTES=UNCHANGED'
            $engineMode='Verify'
        }
        $phase='existing-engine-read-only-verification'
        & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $StageScript -Mode $engineMode -OriginalInstallDir $OriginalInstallDir -InstallDir $InstallDir -HermesHome $HermesHome -ArtifactPath $ArtifactPath -PythonPath $PythonPath
        if ($LASTEXITCODE -ne 0) { throw 'ENGINE_NOT_COMPLETE_PRESERVE_STAGE' }
        Write-Output 'MANAGED_CREATE_STAGE=PASS'
        $exitCode=0
    }
} catch {
    Write-Output ('MANAGED_STAGE_STOP_PHASE='+$phase)
    Write-Output ('MANAGED_STAGE_STOP='+$_.Exception.Message)
    Write-Output ('ACL_RECOVERY_RECORD='+$record)
    Write-Output 'NO_AUTOMATIC_RETRY_ACTIVATION_CREDENTIAL_COPY_REMOTE_WRITE_OR_RESTART'
} finally { $OutputEncoding=$oldEncoding;[Console]::OutputEncoding=$oldConsole }
exit $exitCode
