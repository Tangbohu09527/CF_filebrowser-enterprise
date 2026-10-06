# Stage the approved-create client without touching a live Hermes configuration.
# Uses the already verified release artifact; credentials are referenced, never copied.
[CmdletBinding()]
param(
    [ValidateSet('Stage','Resume','Verify','SelfTest')][string]$Mode='Stage',
    [string]$ArtifactPath=(Join-Path $env:USERPROFILE 'Downloads\filebridge-client-windows-28a4481f.zip'),
    [string]$OriginalInstallDir=(Join-Path $env:USERPROFILE 'CF-FileBridge\client-04c7e717'),
    [string]$InstallDir=(Join-Path $env:USERPROFILE 'CF-FileBridge\client-28a4481f'),
    [string]$HermesHome=(Join-Path $env:LOCALAPPDATA 'hermes'),
    [string]$PythonPath=''
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$utf8=[Text.UTF8Encoding]::new($false)
$oldEncoding=$OutputEncoding
$oldConsole=[Console]::OutputEncoding
$exitCode=1
$stageRootApproved=$false
$phase='local-preflight'

function Assert-LocalPath([string]$Path,[bool]$IsDirectory) {
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\')) { throw 'Local absolute paths required.' }
    $node=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ([bool]$node.PSIsContainer -ne $IsDirectory) { throw 'Path type differs.' }
    while ($null -ne $node) {
        if ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse paths refused.' }
        if ($node -is [IO.FileInfo]) { $node=$node.Directory } else { $node=$node.Parent }
    }
}
function Assert-PrivateNode([string]$Path,[bool]$AllowDefaultOwner=$false) {
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-LocalPath $Path ([bool]$item.PSIsContainer)
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne $script:operatorSid -and -not ($AllowDefaultOwner -and $owner -eq $script:defaultOwner -and $owner -eq 'S-1-5-32-544')) {
        throw 'Owner differs from the verified operator; no broad ownership change.'
    }
    $seen=@{}
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        $id=$rule.IdentityReference.Value
        if (@($script:operatorSid,'S-1-5-18') -notcontains $id -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl) {
            throw 'DACL must remain operator-and-SYSTEM only.'
        }
        if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0) { $seen[$id]=$true }
    }
    if (-not $seen.ContainsKey($script:operatorSid) -or -not $seen.ContainsKey('S-1-5-18')) { throw 'Applicable private access rule missing.' }
}
function New-PrivateDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw 'Destination already exists; preserve it.' }
    Assert-LocalPath (Split-Path -Parent $Path) $true
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($script:operatorSid))
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @($script:operatorSid,'S-1-5-18')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    [IO.Directory]::CreateDirectory($Path,$acl) | Out-Null
    Assert-PrivateNode $Path
    if (-not (Get-Acl -LiteralPath $Path).AreAccessRulesProtected) { throw 'New root still inherits broader rules.' }
}
function Normalize-NewRelease([string]$Path) {
    # Only the new side-by-side release tree. Never traverse the original release.
    $stack=[Collections.Generic.Stack[string]]::new();$stack.Push($Path)
    $nodes=[Collections.Generic.List[string]]::new()
    while ($stack.Count -gt 0) {
        $name=$stack.Pop();Assert-PrivateNode $name $true;$nodes.Add($name)
        if ($nodes.Count -gt 256) { throw 'Unexpected new release tree size.' }
        if ((Get-Item -LiteralPath $name -Force).PSIsContainer) {
            foreach ($child in @(Get-ChildItem -LiteralPath $name -Force)) { $stack.Push($child.FullName) }
        }
    }
    $changed=0
    foreach ($name in $nodes) {
        $acl=Get-Acl -LiteralPath $name
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $script:operatorSid) {
            $before=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
            $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($script:operatorSid))
            if ((Get-Item -LiteralPath $name -Force).PSIsContainer) { [IO.Directory]::SetAccessControl($name,$acl) }
            else { [IO.File]::SetAccessControl($name,$acl) }
            if ((Get-Acl -LiteralPath $name).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -cne $before) {
                throw 'New release DACL changed during owner alignment.'
            }
            $changed++
        }
        Assert-PrivateNode $name
    }
    Write-Output ('NEW_RELEASE_OWNERS_NORMALIZED='+$changed)
    Write-Output 'NEW_RELEASE_NTFS_PRIVATE=PASS'
}
function Write-SameOrNew([string]$Path,[byte[]]$Bytes) {
    if (Test-Path -LiteralPath $Path) {
        Assert-LocalPath $Path $false
        $existing=[IO.File]::ReadAllBytes($Path)
        if ([Convert]::ToBase64String($existing) -cne [Convert]::ToBase64String($Bytes)) { throw 'Existing stage driver differs; no overwrite.' }
        return
    }
    $stream=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
}
function Run-NativeStageSelfTest {
    # Fresh non-secret dummy files only. No Hermes directories, credentials or network.
    $root=Join-Path ([IO.Path]::GetTempPath()) ('cf-create-stage-native-'+[Guid]::NewGuid().ToString('N'))
    New-PrivateDirectory $root
    $file=Join-Path $root 'dummy.txt'
    Write-SameOrNew $file ($utf8.GetBytes('public native test only'))
    $before=(Get-Acl -LiteralPath $file).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    Normalize-NewRelease $root
    $after=(Get-Acl -LiteralPath $file).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    if ($before -cne $after) { throw 'Native owner alignment changed DACL.' }
    Write-SameOrNew $file ($utf8.GetBytes('public native test only'))
    $denied=$false
    try { Write-SameOrNew $file ($utf8.GetBytes('different')) } catch { $denied=$true }
    if (-not $denied -or [IO.File]::ReadAllText($file) -cne 'public native test only') { throw 'Existing content was not protected.' }
    $acl=Get-Acl -LiteralPath $file
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),[Security.AccessControl.FileSystemRights]::Read,
        [Security.AccessControl.AccessControlType]::Allow))
    [IO.File]::SetAccessControl($file,$acl)
    $denied=$false
    try { Normalize-NewRelease $root } catch { $denied=$true }
    if (-not $denied) { throw 'Broad ACL was silently repaired or accepted.' }
    # Only these test-created paths are removed. No recursive deletion of arbitrary directories.
    Remove-Item -LiteralPath $file
    Remove-Item -LiteralPath $root
    Write-Output ('NATIVE_STAGE_CONTEXT='+(@{powershell=$PSVersionTable.PSVersion.ToString();default_owner=$script:defaultOwner} | ConvertTo-Json -Compress))
    Write-Output 'NATIVE_CREATE_STAGE_ACL_AND_RESUME=PASS'
}
try {
    if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
        throw 'Use native Windows PowerShell 5.1 (powershell.exe), not SSH or PowerShell Core.'
    }
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $script:operatorSid=$identity.User.Value;$script:defaultOwner=$identity.Owner.Value
    if ($Mode -eq 'SelfTest') {
        Run-NativeStageSelfTest
        $exitCode=0
    } else {
        $InstallDir=[IO.Path]::GetFullPath($InstallDir)
        $OriginalInstallDir=[IO.Path]::GetFullPath($OriginalInstallDir)
        $HermesHome=[IO.Path]::GetFullPath($HermesHome)
        if ($InstallDir -eq $OriginalInstallDir -or (Split-Path -Parent $InstallDir) -ne (Split-Path -Parent $OriginalInstallDir)) {
            throw 'New release must be a separate sibling directory.'
        }
        foreach ($rel in @('','bin','bin\filebrowser-agentctl.exe','trust','trust\ca.crt','secrets','secrets\runtime-token',
                          'install-inventory.json','filebridge-config.json','client-ready.json','hermes-plugin-settings.json',
                          'plugin','plugin\__init__.py','plugin\plugin.yaml','evidence','evidence\handoff-received.json')) {
            $name=if ($rel) { Join-Path $OriginalInstallDir $rel } else { $OriginalInstallDir }
            Assert-PrivateNode $name
        }
        if (-not (Get-Acl -LiteralPath $OriginalInstallDir).AreAccessRulesProtected) { throw 'Original install root inherits ACL.' }
        Assert-LocalPath $ArtifactPath $false
        if ((Get-FileHash -LiteralPath $ArtifactPath -Algorithm SHA256).Hash -ne 'c23e2aa28363596fec7c56ebfae8fce495cc2b574fe589cc3cef9c177b9e857d') { throw 'Artifact differs from verified ZIP.' }
        if (-not $PythonPath) { $PythonPath=Join-Path $HermesHome 'hermes-agent\venv\Scripts\python.exe' }
        Assert-LocalPath $PythonPath $false
        & $PythonPath -I -S -B -c "import os,sys;sys.exit(0 if os.name=='nt' and sys.version_info>=(3,11) else 1)"
        if ($LASTEXITCODE -ne 0) { throw 'A native Python 3.11+ interpreter is required; none installed or upgraded.' }
        $OutputEncoding=$utf8;[Console]::OutputEncoding=$utf8
        $core=@'
"""Stage a verified create-capable client next to the accepted read-only client.
No Hermes imports/config edits, token copies, approvals or remote writes.
Only the four whitelisted read-only CLI invocations can reach the file service.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import tarfile
import uuid
import zipfile

SOURCE = '28a4481fc2f73363f60bb0f6821bfc50817e99c3'
ZIP_SHA = 'c23e2aa28363596fec7c56ebfae8fce495cc2b574fe589cc3cef9c177b9e857d'
CLIENT_SHA = '7051d72c67160b780785086fe7c59ba4a325aa93db4748855bcbad828d43913c'
SOURCE_TAR_SHA = 'f4cac7f76fbf045665d679dcd49f1cd6c3f42b2281492021a159d085fc11adb9'
OLD_SOURCE = '04c7e717d856d8bf451fc18d7f5ae8cd04fc0c40'
OLD_ZIP_SHA = 'cbd1ec99902dc36d16ed970ae9f2df8805eda988b51c5c60a3b2ab94efc2f17f'
OLD_CLIENT_SHA = 'e3b6ef075f35b5e86999560ac5263cf99f329b7a4f90f04e8c7b5078fe0d0f2a'
CA_SHA = '68073cc4b06e9db8ce2fb065ae9c3fc1cc0b74a5d8b1b5b4f06b9ed8baf6f95a'
ENDPOINT = 'https://192.168.1.233:18443'
REMOTE_SOURCE = 'enterprise-files'
REMOTE_SCOPE = '/wechat-acceptance'
REMOTE_PATH = '/CF-FB-CREATE-20260926-01.txt'
USERNAME = 'hermes-agent-test'
USER_ID = 2
PERMS = {k: k in ('browse','download','create','modify','delete') for k in
         ('api','admin','modify','share','realtime','delete','create','browse','preview','download')}
ZIP_FILES = {'source-sha.txt','go-version.txt','SHA256SUMS','filebrowser-agentctl.exe','filebridge-source.tar.gz'}
PLUGIN_FILES = ('__init__.py','plugin.yaml')
OLD_PLUGIN = {'__init__.py':'350b2c03a7f0f50424986f2d5440081fc0aa2c5a4dca9a52948f8b5fc33141ba',
              'plugin.yaml':'ae20b45c4a23b06fdd9a06a6edbb752d22654bd7b7db609a8f11d6b2d52c892e'}
READ_COMMANDS = {'ping','whoami','capabilities','sources','list','stat','checksum','read'}
CREATE_COMMANDS = {'create-text','approve-create','create-approved','create-status'}
DIRS = ('bin','plugin','audit','evidence','create-state')

class StageError(RuntimeError):
    pass

def need(ok, msg):
    if not ok:
        raise StageError(msg)

def show(name, value):
    print(name+'='+json.dumps(value,ensure_ascii=True),flush=True)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def load(raw):
    def pairs(items):
        result={}
        for k,v in items:
            need(k not in result,'Duplicate JSON key refused.')
            result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(StageError('Non-finite JSON refused.')))

def encoded(obj):
    return (json.dumps(obj,sort_keys=True,indent=2,ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')

def safe(p):
    need(p.is_absolute(),'Local absolute path required.')
    for item in (p,*p.parents):
        s=item.lstat()
        need(not stat.S_ISLNK(s.st_mode) and not getattr(s,'st_file_attributes',0)&0x400,
             'Symlink/reparse path refused.')
    return p

def read(p,limit=65536):
    safe(p)
    s=p.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=limit,'Unsafe file type, link count or size.')
    with p.open('rb') as f:
        opened=os.fstat(f.fileno())
        need(os.path.samestat(s,opened),'File changed while opening.')
        raw=f.read(limit+1)
    need(len(raw)<=limit,'Input exceeds limit.')
    return raw

def put_same_or_new(p,raw):
    """Resume only exact bytes. Partial/different files are preserved, never overwritten."""
    safe(p.parent)
    if os.path.lexists(p):
        need(read(p,max(len(raw),65536))==raw,'Existing staged file differs: '+p.name)
        return
    with p.open('xb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())
    need(read(p,max(len(raw),65536))==raw,'Staged file readback differs.')

def check_artifact(raw):
    need(sha(raw)==ZIP_SHA,'Artifact digest mismatch.')
    blobs={}
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        members=z.infolist()
        need(len(members)==len(ZIP_FILES) and {m.filename for m in members}==ZIP_FILES,
             'Unexpected or duplicate artifact members.')
        for m in members:
            mode=(m.external_attr>>16)&0xffff
            need(not m.is_dir() and not stat.S_ISLNK(mode) and not m.flag_bits&1
                 and m.file_size<=64*1024**2,'Unsafe artifact member.')
            blobs[m.filename]=z.read(m)
    need(blobs['source-sha.txt'].decode('ascii').strip()==SOURCE,'Artifact source differs.')
    need(blobs['go-version.txt'].decode('ascii').strip()=='go version go1.25.0 windows/amd64',
         'Wrong artifact platform/toolchain.')
    sums={}
    for line in blobs['SHA256SUMS'].decode('ascii').splitlines():
        m=re.fullmatch(r'([0-9a-f]{64}) [ *]([^\r\n]+)',line)
        need(m and m[2] in ('filebrowser-agentctl.exe','filebridge-source.tar.gz') and m[2] not in sums,
             'Invalid checksum inventory.')
        sums[m[2]]=m[1]
    need(sums=={'filebrowser-agentctl.exe':CLIENT_SHA,'filebridge-source.tar.gz':SOURCE_TAR_SHA}
         and all(sha(blobs[n])==h for n,h in sums.items()),'Artifact files differ from independent pins.')
    exe=blobs['filebrowser-agentctl.exe']
    need(len(exe)>64 and exe[:2]==b'MZ','Not a Windows executable.')
    offset=struct.unpack_from('<I',exe,0x3c)[0]
    need(64<=offset<=len(exe)-6 and exe[offset:offset+4]==b'PE\x00\x00' and
         struct.unpack_from('<H',exe,offset+4)[0]==0x8664,'Not Windows amd64.')
    plugins={};seen=set();total=0
    with tarfile.open(fileobj=io.BytesIO(blobs['filebridge-source.tar.gz']),mode='r:gz') as t:
        for item in t:
            total+=item.size
            name=item.name
            need(name not in seen and len(seen)<1000 and total<=16*1024**2,'Source archive limits/duplicate.')
            seen.add(name)
            path=PurePosixPath(name)
            need(not path.is_absolute() and not any(p in ('.','..') for p in name.split('/') if p)
                 and not any(c in name for c in ('\\',':','\x00')) and not item.issym() and not item.islnk()
                 and (item.isdir() or item.isreg()) and not getattr(item,'sparse',None),'Unsafe source archive.')
            prefix='integrations/hermes-filebridge/plugin/'
            if name.startswith(prefix) and item.isreg():
                leaf=name[len(prefix):]
                need(leaf in PLUGIN_FILES and leaf not in plugins and item.size<=65536,'Unexpected plugin member.')
                f=t.extractfile(item)
                need(f is not None,'Missing plugin bytes.')
                plugins[leaf]=f.read(65537)
                need(len(plugins[leaf])==item.size,'Incomplete plugin bytes.')
    need(set(plugins)==set(PLUGIN_FILES),'Missing plugin source.')
    # Compile original CRLF bytes; never normalize installed artifact content.
    compile(plugins['__init__.py'],'<verified-plugin>','exec')
    return blobs,plugins

def old_baseline(old,home,sid):
    """Read pinned files only; do not scan sessions or parse the Hermes configuration."""
    safe(old);safe(home)
    raw=read(old/'filebridge-config.json');cfg=load(raw)
    inv=load(read(old/'install-inventory.json'))
    ready=load(read(old/'client-ready.json'))
    need(inv.get('schema')=='cf-filebridge-local-install/v1' and inv.get('source_sha')==OLD_SOURCE
         and inv.get('artifact_sha256')==OLD_ZIP_SHA and inv.get('operator_sid')==sid,'Old install/owner differs.')
    need(sha(read(old/'bin/filebrowser-agentctl.exe',64*1024**2))==OLD_CLIENT_SHA==inv.get('client_sha256')
         and sha(raw)==inv.get('config_sha256') and sha(read(old/'trust/ca.crt'))==CA_SHA,'Old client/config/CA differs.')
    need(cfg.get('base_url')==ENDPOINT and cfg.get('direct_connection') is True and cfg.get('ca_sha256')==CA_SHA
         and cfg.get('ca_file')=='./trust/ca.crt' and cfg.get('token_file')=='./secrets/runtime-token'
         and cfg.get('audit_log')=='./audit/client.jsonl' and cfg.get('local_read_roots')==[]
         and cfg.get('local_write_roots')==[] and cfg.get('allowed_sources')=={
             REMOTE_SOURCE:{'read_roots':['/'],'write_roots':[]}} and not cfg.get('create_text'),
         'Old read-only policy differs; nothing changed.')
    need(ready.get('schema')=='cf-filebridge-client-ready/v1' and ready.get('client_identity_and_list') is True
         and ready.get('remote_scope')==REMOTE_SCOPE and ready.get('client_sha256')==OLD_CLIENT_SHA,'Prior client readiness missing.')
    for n,d in OLD_PLUGIN.items():
        need(sha(read(old/'plugin'/n))==d==inv.get('plugin_sha256',{}).get(n)
             and sha(read(home/'plugins/cf-filebridge'/n))==d,'Old staged/live plugin differs; use a different upgrade checkpoint.')
    # Hash existing credential in memory only. No token bytes copied to new files or stdout.
    token=read(old/'secrets/runtime-token',16384)
    handoff=load(read(old/'evidence/handoff-received.json'))
    need(handoff.get('token_sha256')==sha(token),'Credential changed since original handoff; stop before reuse.')
    paths=[old/'filebridge-config.json',old/'install-inventory.json',old/'client-ready.json',
           old/'hermes-plugin-settings.json',old/'bin/filebrowser-agentctl.exe',old/'trust/ca.crt',
           home/'config.yaml',home/'plugins/cf-filebridge/__init__.py',home/'plugins/cf-filebridge/plugin.yaml',
           old/'plugin/__init__.py',old/'plugin/plugin.yaml',old/'secrets/runtime-token']
    baseline={str(p):sha(read(p,64*1024**2 if p.suffix=='.exe' else 2*1024**2)) for p in paths}
    return cfg,baseline

def expected_files(old,new,cfg,blobs,plugins):
    common=copy.deepcopy(cfg)
    common.update(token_file=str(old/'secrets/runtime-token'),ca_file=str(old/'trust/ca.crt'),
                  audit_log=str(new/'audit/read-client.jsonl'))
    common.pop('create_text',None)
    creation=copy.deepcopy(common)
    creation.update(audit_log=str(new/'audit/create-client.jsonl'),
                    allowed_sources={REMOTE_SOURCE:{'read_roots':['/'],'write_roots':[REMOTE_PATH]}},
                    max_upload_bytes=65536,max_inline_bytes=65536,max_checksum_bytes=1048576,
                    local_read_roots=[],local_write_roots=[],
                    create_text={'enabled':True,'state_dir':str(new/'create-state'),
                        'source':REMOTE_SOURCE,'server_scope':REMOTE_SCOPE,'user_id':USER_ID,
                        'max_bytes':65536,'approval_ttl_seconds':900})
    settings={'client_path':str(new/'bin/filebrowser-agentctl.exe'),'client_sha256':CLIENT_SHA,
              'config_path':str(new/'read-config.json'),'create_enabled':True,
              'create_config_path':str(new/'create-config.json')}
    files={'bin/filebrowser-agentctl.exe':blobs['filebrowser-agentctl.exe'],
           'read-config.json':encoded(common),'create-config.json':encoded(creation),
           'hermes-plugin-settings.json':encoded(settings)}
    files.update({'plugin/'+n:b for n,b in plugins.items()})
    files.update({'evidence/'+n:blobs[n] for n in ZIP_FILES-{'filebrowser-agentctl.exe'}})
    return files

def inventory(args,baseline,files):
    return {'schema':'cf-filebridge-create-stage/v1','source_sha':SOURCE,'artifact_sha256':ZIP_SHA,
            'client_sha256':CLIENT_SHA,'operator_sid':args.sid,'previous_install':str(args.old),
            'install_dir':str(args.new),'hermes_home':str(args.home),'source':REMOTE_SOURCE,
            'server_scope':REMOTE_SCOPE,'target_path':REMOTE_PATH,
            'protected_sha256':baseline,'files_sha256':{n:sha(b) for n,b in files.items()},
            'hermes_config_changed':False,'token_copied':False,'remote_writes':False}

def validate_new_tree(new,files):
    safe(new)
    dirs=set(DIRS)
    names=set(files)|{'stage-core.py','stage-manifest.json','create-stage-ready.json'}
    count=0
    stack=[new]
    while stack:
        p=stack.pop();safe(p)
        for child in p.iterdir():
            count+=1;need(count<=256,'Unexpected staged file count.')
            safe(child)
            rel=child.relative_to(new).as_posix()
            if child.is_dir():
                need(rel in dirs,'Unexpected staged directory; no changes attempted.')
                stack.append(child)
            else:
                allowed=rel in names or re.fullmatch(r'evidence/read-probe-[0-9a-f]{32}\.json',rel) or rel in (
                    'audit/read-client.jsonl','audit/create-client.jsonl')
                need(bool(allowed),'Unexpected staged file; no overwrite.')
                read(child,64*1024**2 if rel.endswith('.exe') else 4*1024**2)
    if (new/'create-state').exists():
        need(not any((new/'create-state').iterdir()),'Creation state is not empty: this is no longer a staging checkpoint.')

def stage(args):
    cfg,baseline=old_baseline(args.old,args.home,args.sid)
    blobs,plugins=check_artifact(read(args.artifact,64*1024**2))
    files=expected_files(args.old,args.new,cfg,blobs,plugins)
    manifest=inventory(args,baseline,files)
    if args.phase=='preflight':
        print('CREATE_ARTIFACT_AND_OLD_BASELINE=PASS',flush=True)
        return
    validate_new_tree(args.new,files)
    old_manifest=args.new/'stage-manifest.json'
    if old_manifest.exists():
        need(load(read(old_manifest))==manifest,'Saved staging manifest or original baseline differs.')
    if args.phase=='install':
        for n in DIRS:
            p=args.new/n
            if p.exists():
                need(safe(p).is_dir(),'Staged directory changed.')
            else:
                p.mkdir(mode=0o700)
        for n,raw in files.items():
            put_same_or_new(args.new/n,raw)
        put_same_or_new(old_manifest,encoded(manifest))
        print('CREATE_CLIENT_FILES_STAGED=PASS\nCREDENTIALS=REFERENCED_NOT_COPIED',flush=True)
    else:
        need(old_manifest.exists(),'Staging manifest missing; use explicit Resume, not Verify.')
        for n,raw in files.items():
            need(read(args.new/n,max(len(raw),65536))==raw,'Staged bytes changed: '+n)
        verify_online(args,manifest)
    _,after=old_baseline(args.old,args.home,args.sid)
    need(after==baseline,'Protected original files changed during staging; no automatic rollback.')
    print('OLD_CLIENT_PLUGIN_CONFIG_AND_CREDENTIAL_BYTES=UNCHANGED\nHERMES_CONFIG_BYTES=UNCHANGED',flush=True)

def cli(new,config,command,data=None,allow_missing=False):
    need(command in ('help','whoami','list','stat'),'This stage can only query help, identity, listing and target metadata.')
    exe=new/'bin/filebrowser-agentctl.exe'
    need(sha(read(exe,64*1024**2))==CLIENT_SHA,'Client digest changed before execution.')
    request={} if data is None else dict(data)
    request.setdefault('request_id','stage-'+uuid.uuid4().hex)
    argv=[str(exe),'--help'] if command=='help' else [str(exe),'--config',str(config),'--input','-',command]
    env={k:v for k,v in os.environ.items() if k.upper() not in {
        'FILEBROWSER_AGENT_TOKEN','SSLKEYLOGFILE','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','FTP_PROXY','NO_PROXY'}}
    try:
        p=subprocess.run(argv,input=encoded(request) if command!='help' else b'',stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,cwd=new,env=env,shell=False,timeout=90)
    except subprocess.TimeoutExpired:
        raise StageError('Read-only probe timed out. No remote write was requested.') from None
    need(len(p.stdout)<=2*1024**2,'Client output exceeds inspection limit.')
    response=load(p.stdout)
    need(isinstance(response,dict) and response.get('schema_version')=='filebrowser-agentctl/v1'
         and response.get('command')==command and type(response.get('ok')) is bool,'Unexpected client response format.')
    if command!='help':
        need(response.get('request_id')==request['request_id'],'Probe request identity mismatch.')
    if response['ok'] is True and p.returncode==0:
        return response
    error=response.get('error') or {}
    if allow_missing and command=='stat' and p.returncode==1 and response['ok'] is False and error.get('code')=='not_found' and error.get('http_status')==404:
        return response
    code=error.get('code')
    show('CREATE_STAGE_CLIENT_ERROR',{'command':command,'code':code if isinstance(code,str) and re.fullmatch(r'[a-z0-9_]{1,80}',code) else 'withheld','exit':p.returncode})
    raise StageError('Read-only client check did not pass. No remote write requested.')

def verify_identity(who):
    perms=who.get('permissions') if isinstance(who,dict) else None
    checks={'username':isinstance(who,dict) and who.get('username')==USERNAME,
            'user_id':isinstance(who,dict) and type(who.get('user_id')) is int and who['user_id']==USER_ID,
            'scope':isinstance(who,dict) and who.get('sources')==[{'name':REMOTE_SOURCE,'scope':REMOTE_SCOPE}],
            'capabilities_exact':isinstance(who,dict) and who.get('capabilities_exact') is True,
            'permissions_exact':isinstance(perms,dict) and set(perms)==set(PERMS) and all(perms[k] is v for k,v in PERMS.items())}
    show('CREATE_STAGE_IDENTITY_CHECKS',checks)
    need(all(checks.values()),'Original enrolled identity/scope/grants differ. No permission changes attempted.')

def plugin_probe(new):
    settings=load(read(new/'hermes-plugin-settings.json'))
    spec=importlib.util.spec_from_file_location('cf_create_stage_probe',new/'plugin/__init__.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    class Ctx:
        def __init__(self,s): self.settings=s;self.tools=[]
        def get_config(self,k,default=None): return self.settings.get(k,default)
        def register_tool(self,**kw): self.tools.append(kw)
    plain=Ctx({k:v for k,v in settings.items() if not k.startswith('create_')})
    module.register(plain)
    need(len(plain.tools)==1 and plain.tools[0]['name']=='filebrowser_files','Creation unexpectedly on by default.')
    ctx=Ctx(settings);module.register(ctx)
    need([(t['name'],t['toolset']) for t in ctx.tools]==[
        ('filebrowser_files','cf_filebridge'),('filebrowser_create_text','cf_filebridge_create')]
         and all(t.get('override') is False for t in ctx.tools),'Optional plugin registration differs.')
    need(set(ctx.tools[0]['schema']['parameters']['properties']['command']['enum'])==READ_COMMANDS
         and set(ctx.tools[1]['schema']['parameters']['properties']['command']['enum'])=={'plan','apply','status'},'Unexpected tool command surface.')
    # Both inputs are rejected before the subprocess boundary. No plan or approval exists.
    for tool,data in ((ctx.tools[0],{'command':'delete','input':{}}),
                      (ctx.tools[1],{'command':'approve-create','input':{}}),
                      (ctx.tools[1],{'command':'apply','input':{'content':'not-authorized'}})):
        r=load(tool['handler'](data))
        need(r.get('ok') is False and r.get('error',{}).get('code')=='invalid_tool_input','Plugin guard failed.')
    print('CREATE_PLUGIN_DEFAULT_OFF=PASS\nCREATE_PLUGIN_LOCAL_REGISTRATION=PASS\nAPPROVAL_NOT_EXPOSED_AS_PLUGIN_TOOL=PASS',flush=True)

def verify_online(args,manifest):
    new=args.new
    help_response=cli(new,None,'help')
    need(READ_COMMANDS|CREATE_COMMANDS<=set(help_response.get('result',{}).get('commands',[])),'New CLI commands missing.')
    who=cli(new,new/'create-config.json','whoami')
    verify_identity(who.get('result'))
    listing=cli(new,new/'read-config.json','list',{'source':REMOTE_SOURCE,'path':'/'})
    r=listing.get('result') or {}
    need(r.get('source')==REMOTE_SOURCE and r.get('path')=='/' and isinstance(r.get('files'),list)
         and isinstance(r.get('folders'),list),'Read-only listing response differs.')
    target=cli(new,new/'create-config.json','stat',{'source':REMOTE_SOURCE,'path':REMOTE_PATH},allow_missing=True)
    need(target.get('ok') is False,'The selected create-test target already exists. No overwrite, no automatic renaming.')
    plugin_probe(new)
    need(not any((new/'create-state').iterdir()),'Unexpected operation state: do not stage over existing plans.')
    _,after=old_baseline(args.old,args.home,args.sid)
    need(after==manifest['protected_sha256'],'Original files changed; preserve staging.')
    show('CREATE_TARGET_PREFLIGHT',{'source':REMOTE_SOURCE,'path':REMOTE_PATH,'exists':False,'write_attempted':False})
    result={'schema':'cf-filebridge-create-client-ready/v1','source_sha':SOURCE,'client_sha256':CLIENT_SHA,
            'operator_sid':args.sid,'old_install':str(args.old),'install_dir':str(new),
            'target_path':REMOTE_PATH,'source':REMOTE_SOURCE,'server_scope':REMOTE_SCOPE,
            'read_only_probes_passed':True,'plugin_registration_checked_locally':True,
            'live_hermes_plugin_enabled':False,'hermes_config_changed':False,'token_copied':False,
            'remote_creation_attempted':False,'approval_created':False}
    put_same_or_new(new/'create-stage-ready.json',encoded(result))
    receipt={'schema':'cf-filebridge-create-stage-read-probes/v1','request_ids':[
        who['request_id'],listing['request_id'],target['request_id']],
        'file_count':len(r['files']),'folder_count':len(r['folders']),'target_exists':False,
        'remote_write_requests':0,'ready_sha256':sha(encoded(result))}
    put_same_or_new(new/'evidence'/('read-probe-'+uuid.uuid4().hex+'.json'),encoded(receipt))
    print('CREATE_CLIENT_READ_ONLY_PROBES=PASS\nCREATE_STATE_EMPTY=PASS',flush=True)
    show('CREATE_CLIENT_READY_EVIDENCE',str(new/'create-stage-ready.json'))
    show('CREATE_PLUGIN_SETTINGS_FILE',str(new/'hermes-plugin-settings.json'))

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--phase',choices=('preflight','install','verify'),required=True)
    for arg in ('old','new','home','artifact'): p.add_argument('--'+arg,type=Path,required=True)
    p.add_argument('--sid',required=True)
    args=p.parse_args()
    need(os.name=='nt' and sys.version_info>=(3,11),'Native Windows Python 3.11+ required for this installer.')
    need(args.new.is_absolute() and args.old.is_absolute() and args.new.parent==args.old.parent and args.new!=args.old,
         'New release must be a separate sibling of the original installation.')
    stage(args)

if __name__=='__main__':
    try: main()
    except Exception as e:
        show('CREATE_STAGE_STOP',str(e) if isinstance(e,StageError) else type(e).__name__)
        print('PRESERVE_BOTH_INSTALLATIONS_NO_OVERWRITE_NO_REMOTE_WRITE_NO_RESTART',flush=True)
        sys.exit(1)
'@
        $common=@('--old',$OriginalInstallDir,'--new',$InstallDir,'--home',$HermesHome,'--artifact',$ArtifactPath,'--sid',$script:operatorSid)
        $phase='artifact-and-original-baseline'
        $core | & $PythonPath -I -S -u -B - --phase preflight @common
        if ($LASTEXITCODE -ne 0) { throw 'Artifact/original baseline failed; no stage installed.' }
        if ($Mode -eq 'Stage') { New-PrivateDirectory $InstallDir }
        else {
            Assert-PrivateNode $InstallDir $true
            if (-not (Get-Acl -LiteralPath $InstallDir).AreAccessRulesProtected) { throw 'Stage root inherits broader ACL.' }
        }
        $stageRootApproved=$true
        Write-Output ('CREATE_INSTALL_DIR='+$InstallDir)
        $driver=Join-Path $InstallDir 'stage-core.py'
        Write-SameOrNew $driver ($utf8.GetBytes($core))
        $phase='stage-new-files'
        if ($Mode -ne 'Verify') {
            $core | & $PythonPath -I -S -u -B - --phase install @common
            if ($LASTEXITCODE -ne 0) { throw 'Staging did not complete. Preserve files; do not delete the original install.' }
        }
        Normalize-NewRelease $InstallDir
        $phase='read-only-client-check'
        $core | & $PythonPath -I -S -u -B - --phase verify @common
        if ($LASTEXITCODE -ne 0) { throw 'Read-only validation did not pass. No approval, upload or overwrite was attempted.' }
        Normalize-NewRelease $InstallDir
        Write-Output 'CREATE_CLIENT_STAGE=PASS'
        Write-Output 'CURRENT_HERMES_STILL_USES_OLD_READ_CLIENT=YES'
        Write-Output 'HERMES_CONFIG_CHANGED=NO'
        Write-Output 'REMOTE_FILE_WRITES=NONE'
        Write-Output 'CREATE_PLAN_OR_APPROVAL_CREATED=NO'
        Write-Output 'TOKEN_COPIED_OR_REISSUED=NO'
        Write-Output 'SERVICES_RESTARTED=NO'
        $exitCode=0
    }
} catch {
    Write-Output ('CREATE_STAGE_STOP_PHASE='+$phase)
    Write-Output ('CREATE_STAGE_STOP='+$_.Exception.Message)
    if ($stageRootApproved) {
        Write-Output ('PRESERVE_NEW_RELEASE='+$InstallDir)
        try { Normalize-NewRelease $InstallDir } catch { Write-Output 'NEW_RELEASE_ACL_REVIEW=REQUIRED' }
    }
    Write-Output 'No automatic rollback, deletion, activation, credential copy, approval or remote write.'
} finally {
    $OutputEncoding=$oldEncoding
    [Console]::OutputEncoding=$oldConsole
}
exit $exitCode
