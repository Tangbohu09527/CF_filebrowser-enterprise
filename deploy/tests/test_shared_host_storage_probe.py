#!/usr/bin/env python3
"""Pure storage evidence contracts; does not mount, boot or access a deployment."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PATH=Path(__file__).resolve().parents[2]/'scripts/tests/shared_host_storage_probe.py'
SPEC=importlib.util.spec_from_file_location('shared_host_storage_probe',PATH)
probe=importlib.util.module_from_spec(SPEC);sys.modules[SPEC.name]=probe;SPEC.loader.exec_module(probe)


class StorageEvidenceTests(unittest.TestCase):
    UUID='6332c534-3906-4231-8f96-699533ec7835'

    def fixture(self):
        return {'disk':{'devices':[{'serial':'cf-test-data','blkid_uuid':self.UUID,'blkid_type':'ext4','size':11*1024**3}]},
                'root_underlay':{'complete':True,'entry_count':0,'tree_sha256':'a'*64},'mounted':False,
                'fstab':[{'what':'UUID='+self.UUID,'where':'/srv/storage','fstype':'ext4'}]}

    def test_only_storage_fstab_entry_is_reported(self):
        text='server:/private /private nfs password=DO-NOT-PRINT 0 0\nUUID='+self.UUID+' /srv/storage ext4 defaults,nofail,x-systemd.device-timeout=5s 0 2\n'
        got=probe.fstab_entries(text)
        self.assertEqual(len(got),1);self.assertEqual(got[0]['what'],'UUID='+self.UUID)
        self.assertEqual(got[0]['options'],['defaults','nofail','x-systemd.device-timeout=5s'])
        self.assertEqual(got[0]['pass'],'2');self.assertNotIn('DO-NOT',json.dumps(got))

    def test_dependencies_preserve_actual_escaped_device_name(self):
        device=r'dev-disk-by\x2duuid-6332c534\x2d3906.device'
        fsck=r'systemd-fsck@dev-disk-by\x2duuid-6332.service'
        self.assertEqual(probe.related_units({'Requires':[device,fsck,'unrelated.service'],'After':[device]}),sorted([device,fsck]))
        with mock.patch.object(probe,'run',return_value=(subprocess.CompletedProcess([],0,b'ActiveState=inactive\nExecMount={ path=/usr/bin/mount ; pid=12 ; code=exited ; status=32 }\n',b''),{})) as run:
            got=probe.unit_state(device)
        self.assertEqual(run.call_args.args[0][2],device)
        self.assertEqual(got['ExecMount'],{'pid':'12','code':'exited','status':'32'})

    def test_precise_fixed_paths_without_raw_docker_error(self):
        raw='failed to start container PRIVATE-TOKEN: mounting "/srv/storage/cf-filebrowser-enterprise/.storage-identity" to "/run/filebrowser-storage-identity": no such file or directory; env=PRIVATE-PASSWORD'
        got=probe.error_evidence(raw)
        self.assertIn('/srv/storage/cf-filebrowser-enterprise/.storage-identity',got['fixed_paths'])
        self.assertIn('/run/filebrowser-storage-identity',got['fixed_paths'])
        self.assertIn('missing-path',got['categories'])
        self.assertNotIn('PRIVATE',json.dumps(got))
        entry=probe.error_evidence('exec "/opt/filebrowser-enterprise/scripts/container-entrypoint.sh": no such file or directory')
        self.assertEqual(entry['fixed_paths'],['/opt/filebrowser-enterprise/scripts/container-entrypoint.sh'])

    def test_journal_order_and_filtered_messages(self):
        device='dev-test.device';cid='a'*64
        rows=[{'__MONOTONIC_TIMESTAMP':'9000000','UNIT':device,'MESSAGE':'Timed out waiting for device dev-test.device.','JOB_RESULT':'timeout'},
              {'__MONOTONIC_TIMESTAMP':'30000000','_SYSTEMD_UNIT':'docker.service','MESSAGE':'failed to start container '+cid+' PRIVATE-TOKEN no such file or directory'},
              {'__MONOTONIC_TIMESTAMP':'1','UNIT':'unrelated.service','MESSAGE':'PRIVATE-CONFIG'},
              {'__MONOTONIC_TIMESTAMP':'2','UNIT':'srv-storage.mount','MESSAGE':'srv-storage.mount TOKEN=PRIVATE'}]
        got=probe.journal_records('\n'.join(json.dumps(r) for r in rows),[device,'srv-storage.mount','docker.service'],cid)
        self.assertEqual([v['monotonic_us'] for v in got],[2,9000000,30000000])
        self.assertEqual(got[1]['JOB_RESULT'],'timeout');self.assertIn('Timed out waiting',got[1]['message'])
        self.assertNotIn('PRIVATE',json.dumps(got))

    def test_underlay_detects_new_directory_file_or_changed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            before=probe.underlay_tree(directory)
            Path(directory,'unexpected').mkdir();Path(directory,'unexpected','database.db').write_bytes(b'private business body')
            after=probe.underlay_tree(directory)
            self.assertEqual(before['entry_count'],0);self.assertEqual(after['entry_count'],2)
            self.assertNotEqual(before['tree_sha256'],after['tree_sha256'])
            self.assertNotIn('private business body',json.dumps(after))
            Path(directory,'unexpected','database.db').write_bytes(b'changed business body')
            self.assertNotEqual(after['tree_sha256'],probe.underlay_tree(directory)['tree_sha256'])

    def test_same_disk_requires_serial_uuid_filesystem_and_size(self):
        before=self.fixture();self.assertTrue(probe.same_disk(before,self.fixture()))
        for field,value in (('serial','wrong'),('blkid_uuid','bad'),('blkid_type','xfs'),('size',1)):
            after=self.fixture();after['disk']['devices'][0][field]=value
            with self.subTest(field=field):self.assertFalse(probe.same_disk(before,after))
        after=self.fixture();after['root_underlay']['complete']=False
        self.assertFalse(probe.unchanged_underlay(before,after))

    def test_manual_mount_refuses_changed_or_wrong_disk_without_executing(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(probe,'GUEST',Path(directory)):
            before=self.fixture();after=self.fixture();after['disk']['devices'][0]['blkid_uuid']='wrong'
            Path(directory,'storage-before.json').write_text(json.dumps(before));Path(directory,'storage-failure.json').write_text(json.dumps(after))
            with mock.patch.object(probe,'run') as run:
                result=probe.mount_diagnostic()
            self.assertFalse(result['attempted']);run.assert_not_called()

    def test_single_manual_mount_never_claims_automatic_recovery(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(probe,'GUEST',Path(directory)):
            for phase in ('before','failure'):Path(directory,'storage-'+phase+'.json').write_text(json.dumps(self.fixture()))
            with mock.patch.object(probe,'run',return_value=(subprocess.CompletedProcess([],0,b'',b''),{'exit_code':0})) as run, mock.patch.object(probe,'collect',return_value={'mounted':True}):
                result=probe.mount_diagnostic()
            run.assert_called_once_with(['mount','--','/srv/storage'],30)
            self.assertTrue(result['attempted']);self.assertTrue(result['diagnostic_only']);self.assertFalse(result['automatic_reboot_recovery'])


if __name__=='__main__':unittest.main()
