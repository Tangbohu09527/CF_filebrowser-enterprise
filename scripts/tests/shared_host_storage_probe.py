#!/usr/bin/env python3
"""Bounded storage boot evidence, only inside the marked disposable CI guest."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

GUEST = Path('/root/cf-verification')
STORAGE = Path('/srv/storage')
SERIAL = 'cf-test-data'
UUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
UNIT = r'[A-Za-z0-9_.:@\\-]{1,240}'
FIXED = (
 '/srv/storage/cf-filebrowser-enterprise/.storage-identity',
 '/srv/storage/cf-filebrowser-enterprise/files',
 '/srv/storage/cf-filebrowser-enterprise/backups',
 '/srv/storage/cf-filebrowser-enterprise', '/srv/storage',
 '/opt/cf-filebrowser-enterprise/scripts/container-entrypoint.sh',
 '/opt/filebrowser-enterprise/scripts/container-entrypoint.sh',
 '/run/filebrowser-storage-identity', '/srv/filebrowser/files',
 '/etc/cf-filebrowser-enterprise/storage.identity',
 '/etc/cf-filebrowser-enterprise/config.yaml',
 '/etc/cf-filebrowser-enterprise/secrets', '/etc/cf-filebrowser-enterprise/tls',
 '/var/lib/cf-filebrowser-enterprise', '/var/cache/cf-filebrowser-enterprise',
)
PROPS = ('Id','LoadState','ActiveState','SubState','Result','What','Where','Requires','Wants',
 'After','Before','BindsTo','TriggeredBy','JobTimeoutUSec','JobRunningTimeoutUSec',
 'ActiveEnterTimestampMonotonic','ActiveExitTimestampMonotonic',
 'InactiveEnterTimestampMonotonic','InactiveExitTimestampMonotonic',
 'ExecMainCode','ExecMainStatus','ExecMainStartTimestampMonotonic','ExecMainExitTimestampMonotonic','ExecMount','FragmentPath','SourcePath','DropInPaths')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(argv, timeout=10):
    start = time.monotonic_ns() // 1000
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
        return p, {'start_monotonic_us': start, 'end_monotonic_us': time.monotonic_ns() // 1000,
                   'exit_code': p.returncode, 'timed_out': False}
    except OSError:
        return subprocess.CompletedProcess(argv, 127, b'', b''), {
            'start_monotonic_us': start, 'end_monotonic_us': time.monotonic_ns() // 1000,
            'exit_code': None, 'timed_out': False, 'spawn_failed': True}
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, b'', b''), {
            'start_monotonic_us': start, 'end_monotonic_us': time.monotonic_ns() // 1000,
            'exit_code': None, 'timed_out': True}


def json_command(argv, timeout=10):
    p, timing = run(argv, timeout)
    if p.returncode or len(p.stdout) > 2 * 1024 * 1024:
        return None, timing
    try:
        return json.loads(p.stdout), timing
    except (ValueError, UnicodeError):
        return None, timing


def fstab_entries(text):
    result = []
    for number, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if line.lstrip().startswith('#') or len(fields) < 2 or fields[1] != '/srv/storage':
            continue
        source = fields[0]
        valid_source = re.fullmatch('UUID=' + UUID, source) is not None
        options = fields[3].split(',') if len(fields) > 3 else []
        result.append({'line': number, 'what': source if valid_source else 'invalid-source:' + digest(source.encode()),
            'where': fields[1], 'fstype': fields[2] if len(fields)>2 and fields[2] in ('ext4','xfs','auto') else 'invalid',
            'options': [x if re.fullmatch(r'(?:defaults|noauto|auto|nofail|fail|ro|rw|x-systemd\.[a-z-]+=[0-9]+[a-z]*)', x) else 'unrecognized-option' for x in options],
            'dump': fields[4] if len(fields)>4 and fields[4].isdigit() else None,
            'pass': fields[5] if len(fields)>5 and fields[5].isdigit() else None,
            'field_count': len(fields)})
    return result


def error_evidence(raw):
    text = raw.decode('utf8', 'replace') if isinstance(raw, bytes) else str(raw)
    paths = [path for path in FIXED if re.search(re.escape(path) + r'(?=$|[\s"\x27:,;])', text)]
    lower = text.lower()
    categories = [name for needle, name in (
        ('no such file or directory','missing-path'),('bind source path does not exist','missing-bind-source'),
        ('permission denied','permission-denied'),('timed out','timeout'),('wrong fs type','wrong-filesystem'),
        ('bad superblock','bad-superblock'),('bad option','bad-mount-option'),("can't find uuid",'uuid-not-found'),
        ('failed to start container','container-start-failed')) if needle in lower]
    return {'categories': categories or (['unclassified'] if text else []), 'fixed_paths': paths,
            'private_error_sha256': digest(text.encode()), 'private_error_bytes': len(text.encode())}


def path_state(path):
    try:
        info = Path(path).lstat()
        return {'exists': True, 'kind': 'symlink' if stat.S_ISLNK(info.st_mode) else 'directory' if stat.S_ISDIR(info.st_mode) else 'regular' if stat.S_ISREG(info.st_mode) else 'other',
                'mode': oct(stat.S_IMODE(info.st_mode)), 'uid': info.st_uid, 'gid': info.st_gid,
                'device': info.st_dev, 'inode': info.st_ino, 'size': info.st_size}
    except FileNotFoundError:
        return {'exists': False}


def underlay_tree(path):
    """No symlink traversal or file-body output; digest also detects changed bytes."""
    path = Path(path)
    entries = []
    pending = list(path.iterdir()) if path.is_dir() else []
    total = 0
    while pending:
        p = pending.pop()
        if len(entries) >= 128:
            return {'complete': False, 'reason': 'entry-limit', 'entry_count': len(entries)}
        info = path_state(p)
        item = {**info, 'relative_path_sha256': digest(str(p.relative_to(path)).encode())}
        if info.get('kind') == 'directory':
            pending.extend(p.iterdir())
        elif info.get('kind') == 'regular':
            total += info['size']
            if total > 32 * 1024 * 1024:
                return {'complete': False, 'reason': 'byte-limit', 'entry_count': len(entries)}
            item['file_sha256'] = digest(p.read_bytes())
        entries.append(item)
    entries.sort(key=lambda value: value['relative_path_sha256'])
    return {'complete': True, 'entry_count': len(entries), 'tree_sha256': digest(json.dumps(entries, sort_keys=True).encode()),
            'entries': entries, 'business_path_exists': os.path.lexists(path/'cf-filebrowser-enterprise')}


def root_underlay():
    # Caller uses an unshared mount namespace. No recursive bind: inspect the
    # root filesystem's covered directory, not the mounted business filesystem.
    view = Path(tempfile.mkdtemp(prefix='root-view-', dir=GUEST))
    for argv in (['mount','--bind','/',str(view)], ['mount','-o','remount,bind,ro',str(view)]):
        p, _ = run(argv)
        if p.returncode:
            return {'complete': False, 'reason': 'readonly-root-view-unavailable'}
    target = view/'srv/storage'
    if target.exists() and target.stat().st_dev != Path('/').stat().st_dev:
        return {'complete': False, 'reason': 'root-view-device-mismatch'}
    # The private namespace is destroyed on exit. Do not recursively delete a
    # mounted view. The empty private mountpoint stays in this disposable guest.
    return underlay_tree(target)


def lifecycle_snapshot(absent=False):
    """Disposable guest only: bounded digests, never credentials or file bodies."""
    if not Path('/etc/cf-shared-host-disposable').is_file():
        raise RuntimeError('disposable guest marker required')
    storage = Path('/srv/storage/cf-filebrowser-enterprise')
    if absent:
        if run(['mountpoint', '-q', '/srv/storage'])[0].returncode == 0:
            raise RuntimeError('missing-mount snapshot requires an absent mount')
        rows = fstab_entries(Path(GUEST, 'fstab.saved').read_text())
        if len(rows) != 1 or rows[0]['fstype'] != 'ext4' or not rows[0]['what'].startswith('UUID='):
            raise RuntimeError('verified ext4 test fstab required')
        alias = '/dev/disk/by-uuid/' + rows[0]['what'][5:]
        info, _ = json_command(['lsblk', '--json', '--nodeps', '--output', 'SERIAL,FSTYPE,UUID', alias])
        devices = (info or {}).get('blockdevices', [])
        if len(devices) != 1 or devices[0].get('serial') != 'cf-test-data' or devices[0].get('uuid') != rows[0]['what'][5:] or devices[0].get('fstype') != 'ext4':
            raise RuntimeError('test disk identity mismatch')
        view = Path(tempfile.mkdtemp(prefix='disk-readonly-', dir=GUEST))
        # Private namespace, no journal replay and no writes to the original disk.
        if run(['mount', '-o', 'ro,noload', alias, str(view)])[0].returncode:
            raise RuntimeError('readonly test disk snapshot unavailable')
        storage = view / 'cf-filebrowser-enterprise'
    result = {}
    for name, path in (('disk', storage), ('config', Path('/etc/cf-filebrowser-enterprise')), ('data', Path('/var/lib/cf-filebrowser-enterprise'))):
        if not path.is_dir():
            raise RuntimeError('required persistence directory missing')
        tree = underlay_tree(path)
        if not tree.get('complete'):
            raise RuntimeError('persistence snapshot limit exceeded')
        result[name] = {key: tree[key] for key in ('tree_sha256', 'entry_count')}
    root = root_underlay()
    if not root.get('complete') or root.get('business_path_exists'):
        raise RuntimeError('root underlay is incomplete or contains business data')
    result['root_underlay'] = {key: root[key] for key in ('tree_sha256', 'entry_count', 'business_path_exists')}
    return result


def block_state():
    data, timing = json_command(['lsblk','--json','--bytes','--output','NAME,PATH,TYPE,SERIAL,FSTYPE,UUID,MAJ:MIN,SIZE'])
    found = []
    def visit(items):
        for value in items:
            if value.get('serial') == SERIAL or value.get('path') == '/dev/vdb':
                found.append({k:value.get(k) for k in ('name','path','type','serial','fstype','uuid','maj:min','size')})
            visit(value.get('children', []))
    if isinstance(data, dict): visit(data.get('blockdevices', []))
    for disk in found:
        path = disk.get('path', '')
        if not re.fullmatch(r'/dev/[a-z0-9]+', path): continue
        p, _ = run(['blkid','-o','export',path])
        values = dict(line.split('=',1) for line in p.stdout.decode('utf8','replace').splitlines() if '=' in line)
        disk['blkid_uuid'] = values.get('UUID')
        disk['blkid_type'] = values.get('TYPE')
        p, udev_timing = run(['udevadm','info','--query=property','--name',path])
        values = dict(line.split('=',1) for line in p.stdout.decode('utf8','replace').splitlines() if '=' in line)
        disk['udev'] = {k:values[k][:512] for k in ('DEVPATH','DEVNAME','DEVTYPE','ID_SERIAL','ID_SERIAL_SHORT',
            'ID_FS_TYPE','ID_FS_UUID','SYSTEMD_READY','TAGS','CURRENT_TAGS','USEC_INITIALIZED') if k in values}
        disk['udev_query'] = udev_timing
        uuid = disk['blkid_uuid']
        if isinstance(uuid,str) and re.fullmatch(UUID,uuid):
            link = Path('/dev/disk/by-uuid')/uuid
            disk['by_uuid'] = {'path':str(link),'exists':link.exists(),'target':os.path.realpath(link),
                               'matches_device':link.exists() and os.path.samefile(link,path)}
    return {'observed':data is not None,'devices':found,'timing':timing}


def unit_state(name):
    if not re.fullmatch(UNIT, name): raise ValueError('invalid discovered unit name')
    p, timing = run(['systemctl','show',name,'--no-pager','--property='+','.join(PROPS)])
    raw = dict(line.split('=',1) for line in p.stdout.decode('utf8','replace').splitlines() if '=' in line)
    result = {'queried_unit':name,'query':timing}
    for key in PROPS:
        if key not in raw: continue
        value = raw[key]
        if key == 'ExecMount':
            result[key] = {k:v for k,v in re.findall(r'(code|status|pid)=([A-Za-z0-9_/-]+)',value)}
        elif key.endswith('Monotonic') or key in ('ExecMainCode','ExecMainStatus'):
            result[key] = int(value) if value.isdigit() else None
        elif key in ('Requires','Wants','After','Before','BindsTo','TriggeredBy'):
            result[key] = [n for n in value.split() if re.fullmatch(UNIT,n)][:40]
        else:
            result[key] = value[:512]
    return result


def related_units(mount):
    return sorted({n for field in ('Requires','Wants','After','BindsTo') for n in mount.get(field,[])
                   if n.endswith('.device') or (n.startswith('systemd-fsck') and n.endswith('.service'))})[:8]


def storage_units(record, before):
    """Recover only the verified test disk's names, even after job unloading."""
    names=set(related_units(record.get('mount',{}))) | set(related_units(before.get('mount',{})))
    names.update(n for n in before.get('related_units',{}) if re.fullmatch(UNIT,n))
    identifiers=[]
    entries=record.get('fstab',[])
    disks=[d for d in record.get('disk',{}).get('devices',[]) if d.get('serial')==SERIAL]
    if len(entries)==1 and len(disks)==1:
        d=disks[0];uuid=d.get('blkid_uuid','');path=d.get('path','')
        if isinstance(uuid,str) and isinstance(path,str) and re.fullmatch(UUID,uuid) and entries[0].get('what')=='UUID='+uuid and d.get('blkid_type')=='ext4' and re.fullmatch(r'/dev/[a-z0-9]+',path):
            identifiers=[uuid,path]
            for value in (path,'/dev/disk/by-uuid/'+uuid):
                for option in ('--suffix=device','--template=systemd-fsck@.service'):
                    p,_=run(['systemd-escape','--path',option,value])
                    name=p.stdout.decode('ascii','replace').strip()
                    if p.returncode or not re.fullmatch(UNIT,name):raise ValueError('test disk unit escaping failed')
                    names.add(name)
    return sorted(names)[:16],identifiers


def unit_configuration(name):
    """Selected directives and source filenames, never a raw unit/config dump."""
    if not re.fullmatch(UNIT,name):raise ValueError('invalid unit configuration name')
    p,timing=run(['systemctl','cat','--no-pager',name])
    value={'query':timing,'files':[],'directives':[],'complete':p.returncode==0 and len(p.stdout)<=65536}
    if not value['complete']:return value
    allowed={'After','Before','Requires','Wants','BindsTo','DefaultDependencies','What','Where','Type','Options',
             'JobTimeoutSec','JobRunningTimeoutSec','TimeoutSec','TimeoutStartSec','TimeoutStopSec'}
    for line in p.stdout.decode('utf8','replace').splitlines():
        if line.startswith('# /') and re.fullmatch(r'# /(?:run|etc|usr/lib|lib)/systemd/[A-Za-z0-9_./@\\-]+',line):
            value['files'].append(line[2:])
        key,sep,content=line.partition('=')
        if sep and key in allowed and len(line)<=1000 and not re.search(r'(?i)password|token|secret|authorization',content):
            value['directives'].append(line)
    value['files']=value['files'][:16];value['directives']=value['directives'][:80]
    return value


def journal_records(raw, units, container_id, identifiers=()):
    records = []
    for line in raw.splitlines():
        try: item=json.loads(line)
        except (ValueError,UnicodeError): continue
        msg=item.get('MESSAGE','')
        if not isinstance(msg,str): continue
        unit=item.get('UNIT') or item.get('_SYSTEMD_UNIT') or ''
        related=unit in units or any(n in msg for n in units)
        related=related or any(re.search(re.escape(n)+r'(?=$|[^a-zA-Z0-9])',msg) for n in identifiers)
        docker=unit=='docker.service' and (container_id in msg or container_id[:12] in msg) if container_id else False
        if not related and not docker: continue
        mono=str(item.get('__MONOTONIC_TIMESTAMP',''))
        if not mono.isdigit(): continue
        record={'monotonic_us':int(mono),'unit':unit[:240],**error_evidence(msg)}
        if re.fullmatch(UNIT,str(item.get('UNIT',''))):record['UNIT']=item['UNIT']
        if unit != 'docker.service' and item.get('_SYSTEMD_UNIT') != 'docker.service':
            # Only selected mount/device/fsck or PID1 messages; no general system
            # journal or Docker message bodies. Known fixture UUID/unit paths are
            # diagnostic identifiers, not authentication values.
            if not re.search(r'(?i)(password|token|secret|authorization)\s*[:=]',msg):
                record['message']=msg[:700]
        for key in ('JOB_TYPE','JOB_RESULT'):
            if re.fullmatch(r'[a-z-]{1,40}',str(item.get(key,''))): record[key]=item[key]
        records.append(record)
        if len(records)>=160: break
    return sorted(records,key=lambda x:x['monotonic_us'])


def collect(phase):
    record={'schema':'cf-storage-boot/v1','phase':phase,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'sample_monotonic_us':time.monotonic_ns()//1000,'disk':block_state()}
    record['fstab']=fstab_entries(Path('/etc/fstab').read_text())
    record['mount']=unit_state('srv-storage.mount')
    saved=GUEST/'storage-before.json'
    before=json.loads(saved.read_bytes()) if saved.exists() else {}
    deps,identifiers=storage_units(record,before)
    record['related_units']={name:unit_state(name) for name in deps}
    record['docker_unit']=unit_state('docker.service')
    record['mounted']=run(['mountpoint','--quiet',str(STORAGE)])[0].returncode==0
    record['fixed_paths']={path:path_state(path) for path in FIXED if not path.startswith(('/run/','/srv/filebrowser/','/opt/filebrowser-'))}
    ids,_=run(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project=cf-filebrowser'])
    names=ids.stdout.decode().split();container_id=names[0] if len(names)==1 and re.fullmatch(r'[0-9a-f]{64}',names[0]) else ''
    if container_id:
        data,_=json_command(['docker','inspect',container_id])
        if isinstance(data,list) and data:
            value=data[0];state=value.get('State',{})
            record['container']={'id':container_id,'image':value.get('Image'),'status':state.get('Status'),
                'running':state.get('Running'),'exit_code':state.get('ExitCode'),'started_at':state.get('StartedAt'),
                'finished_at':state.get('FinishedAt'),'error':error_evidence(state.get('Error','')),
                'binds':[{'source':v.get('Source'),'destination':v.get('Destination'),'source_state':path_state(v['Source'])}
                         for v in value.get('Mounts',[]) if v.get('Type')=='bind' and v.get('Source') in FIXED]}
    # Include preboot dependencies and systemd-escaped verified disk candidates.
    record['unit_candidates']=deps
    record['unit_configurations']={name:unit_configuration(name) for name in ['srv-storage.mount',*deps]}
    units=['srv-storage.mount',*deps,'docker.service']
    argv=['journalctl','--boot','--no-pager','--output=json','--lines=350']
    for name in units: argv += ['--unit',name]
    p,timing=run(argv,15)
    record['journal']={'query':timing,'private_bytes':len(p.stdout),'private_sha256':digest(p.stdout),
                       'events':journal_records(p.stdout,units,container_id,identifiers) if len(p.stdout)<=2*1024*1024 else [],
                       'within_byte_limit':len(p.stdout)<=2*1024*1024}
    p,_=run(['journalctl','--boot','--no-pager','--output=json','--lines=1000','_PID=1'],15)
    record['pid1_events']=journal_records(p.stdout,units,container_id,identifiers) if len(p.stdout)<=2*1024*1024 else []
    discovered={e['unit'] for e in record['journal']['events']+record['pid1_events']
                if re.fullmatch(UNIT,e['unit']) and (e['unit'].endswith('.device') or e['unit'].startswith('systemd-fsck@'))}
    for name in sorted(discovered-set(deps))[:8]:
        record['related_units'][name]=unit_state(name)
        record['unit_configurations'][name]=unit_configuration(name)
    names=[v['name'] for v in record['disk']['devices'] if v.get('serial')==SERIAL and re.fullmatch(r'[a-z0-9]+',str(v.get('name','')))]
    p,_=run(['journalctl','--boot','--dmesg','--no-pager','--output=json','--lines=600'],15)
    record['test_disk_kernel_events']=journal_records(p.stdout,names,'') if len(p.stdout)<=2*1024*1024 else []
    data,timing=json_command(['unshare','--mount','--propagation','private',sys.executable,'-B',str(Path(__file__).resolve()),'underlay'],20)
    record['root_underlay']=data if isinstance(data,dict) else {'complete':False,'reason':'underlay-query-failed','query':timing}
    record['end_monotonic_us']=time.monotonic_ns()//1000
    return record


def same_disk(before, after):
    def identity(record):
        devices=[v for v in record.get('disk',{}).get('devices',[]) if v.get('serial')==SERIAL]
        if len(devices)!=1:return None
        d=devices[0]
        if d.get('blkid_type')!='ext4' or not re.fullmatch(UUID,str(d.get('blkid_uuid',''))):return None
        return d.get('serial'),d['blkid_uuid'],d['blkid_type'],d.get('size')
    return identity(before) is not None and identity(before)==identity(after)


def unchanged_underlay(before, after):
    a,b=before.get('root_underlay',{}),after.get('root_underlay',{})
    return a.get('complete') is True and b.get('complete') is True and a.get('tree_sha256')==b.get('tree_sha256')



def mount_diagnostic():
    before=json.loads((GUEST/'storage-before.json').read_bytes())
    failed=json.loads((GUEST/'storage-failure.json').read_bytes())
    result={'diagnostic_only':True,'automatic_reboot_recovery':False,'attempted':False}
    if failed.get('mounted') or not same_disk(before,failed) or not unchanged_underlay(before,failed):
        return {**result,'refusal':'disk-or-underlay-precondition'}
    disks=[v for v in failed['disk']['devices'] if v.get('serial')==SERIAL]
    entries=failed.get('fstab',[])
    if len(entries)!=1 or entries[0].get('what')!='UUID='+disks[0]['blkid_uuid'] or entries[0].get('fstype')!='ext4':
        return {**result,'refusal':'fstab-does-not-identify-the-verified-test-disk'}
    p,timing=run(['mount','--','/srv/storage'],30)
    return {**result,'attempted':True,'command':['mount','--','/srv/storage'], 'command_result':timing,
            'error':error_evidence(p.stderr),'post_attempt':collect('manual')}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=('before','after','failure','underlay','mount-diagnostic','control-5s','control-90s-before','control-90s'))
    phase=parser.parse_args().phase
    if sys.platform!='linux' or os.geteuid()!=0 or Path('/etc/cf-shared-host-disposable').read_text().strip()!='cf-verification-1':
        parser.error('requires the marked disposable service guest')
    os.umask(0o077)
    if phase=='underlay':
        print(json.dumps(root_underlay(),sort_keys=True));return 0
    result=mount_diagnostic() if phase=='mount-diagnostic' else collect(phase)
    path=GUEST/('storage-'+phase+'.json')
    with path.open('x') as stream:json.dump(result,stream,sort_keys=True)
    print(json.dumps(result,sort_keys=True));return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except (OSError,ValueError,KeyError) as error:
        print(json.dumps({'schema':'cf-storage-boot/v1','collection_failed':type(error).__name__}))
        raise SystemExit(1)
