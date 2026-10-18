"""Current host lease + real native TLS worker component; service API is a spy.

Official model/Gateway/FileBrowser integration is recorded separately. This
component does not claim actual WeChat ingestion or a production service run.
"""
import hashlib
import io
import json
import unittest
import zipfile
from unittest.mock import patch
import test_inbound_host as support

products = __import__(support.spec.name + ".products", fromlist=["products"])
TOOL="filebrowser_ingest_product_zip"

class ProductIngestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        support.HostControlTests.setUpClass()

    def setUp(self):
        self.fixture=support.HostControlTests("test_consumer_deadline_requires_live_scope_and_revokes_copied_context")
        self.fixture.make_adapter=False
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f=self.fixture
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,"w") as archive:
            archive.writestr("主图/图片 (1).png",b"synthetic immutable image bytes")
        f.body=stream.getvalue();f.mime="application/zip"
        f.response_transform=lambda data:data["attachments"][0].update(filename="商品 图包 (1).zip")
        f.raw["consumer_tools"]=[TOOL]
        f.config=support.control.HostConfig.from_context(support.Settings(f.raw))
        f.client=support.control.ControlClient(f.config)
        f.bridge=support.inbound.HostBridge(str(f.worker),f.worker_hash)
        f.adapter=support.host.HostAdapter(f.client,f.bridge,downstream_tools=[TOOL])
        f.addCleanup(f.adapter.close)
        self.calls=[];self.streams=[];self.wrong_identity=False

    def trusted(self,_ctx):
        binding,_,guard=support.host.capture_product_inbound_context(5)
        if self.wrong_identity:binding["enterprise_identity_id"]="wrong"
        return binding,guard,"source1","/products",None

    def client(self,_ctx,command,data,*,active,stream=None,**kwargs):
        active();self.calls.append((command,data))
        if stream is not None:
            self.streams.append(stream.read());self.assertEqual(self.streams[-1],self.fixture.body)
            self.assertEqual(data["expected_sha256"],hashlib.sha256(self.fixture.body).hexdigest())
            self.assertEqual(data["path"],"/products/incoming/1/商品 图包 (1).zip")
        return {"ok":True,"result":{"state":"inspected"} if command=="product-inspect" else {}}

    def invoke(self,attachment=5):
        f=self.fixture
        with patch.object(products,"_trusted",side_effect=self.trusted),patch.object(products,"_client",side_effect=self.client):
            handler=products.ingest_handler(support.Settings(f.raw))
            return json.loads(f.adapter.middleware(TOOL,{"attachment_id":attachment},handler,
                              session_id="product-ingest",task_id="product-ingest",turn_id="turn-ingest"))

    def test_current_lease_native_download_workcopy_stream_and_repeat(self):
        result=self.invoke();self.assertTrue(result["ok"])
        self.assertEqual([c for c,_ in self.calls],["mkdir","mkdir","upload-stream","product-inspect"])
        self.assertEqual(self.fixture.download_calls,1)
        self.assertTrue(self.invoke()["ok"])
        self.assertEqual(self.fixture.download_calls,1)
        self.assertEqual(len(self.streams),2)
        self.fixture.adapter.on_session_end(session_id="product-ingest")
        self.assertFalse(self.invoke()["ok"])
        self.assertEqual(len(self.streams),2)

    def test_identity_or_attachment_mismatch_never_uploads(self):
        self.wrong_identity=True
        self.assertFalse(self.invoke()["ok"]);self.assertEqual(self.calls,[])
        self.wrong_identity=False
        self.assertFalse(self.invoke(99)["ok"]);self.assertEqual(self.calls,[])
        self.assertEqual(self.fixture.download_calls,0)

    def test_config_capacity_explicit_128mib_and_higher_denial(self):
        raw={**self.fixture.raw,"max_bytes":128*1024*1024}
        self.assertEqual(support.control.HostConfig.from_context(support.Settings(raw)).max_bytes,128*1024*1024)
        with self.assertRaises(support.inbound.BridgeError):
            support.control.HostConfig.from_context(support.Settings({**raw,"max_bytes":128*1024*1024+1}))
        default=dict(raw);default.pop("max_bytes")
        self.assertEqual(support.control.HostConfig.from_context(support.Settings(default)).max_bytes,64*1024*1024)

if __name__=="__main__":unittest.main()
