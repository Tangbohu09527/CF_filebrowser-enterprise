import asyncio
import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1] / "plugin"
spec = importlib.util.spec_from_file_location("filebridge_products_test", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
products = __import__(spec.name + ".products", fromlist=["products"])
MODULE = "cf_agent_gateway.hermes.return_bridge.plugin"
BINDING = {"dispatch_id": 12, "message_id": 25, "enterprise_identity_id": 7, "thread_id": 8,
           "account_id": "account", "conversation_id": "private", "conversation_type": "private",
           "profile_reference": "profile", "profile_revision": 3, "session_id": "session"}

class Context:
    def __init__(self):
        self.values = {"product_enabled": True, "product_source": "enterprise", "product_root": "/materials",
                       "product_allowed_bindings": [{k: BINDING[k] for k in products._BINDING_FIELDS}]}
        self.tools = {}
    def get_config(self, key, default=None): return self.values.get(key, default)
    def register_tool(self, **tool): self.tools[tool["name"]] = tool

class ProductToolsTests(unittest.TestCase):
    def setUp(self):
        self.context = Context()
        self.calls = []
        self.active = True
        self.module = types.ModuleType(MODULE)
        def guard():
            if not self.active: raise ValueError("task_expired")
        def capture(): return dict(BINDING), guard
        def prepare(**kwargs):
            kwargs["check_active"]()
            self.calls.append(kwargs)
            return {"file_ref": "enterprise-current-only", "kind": "file", "filename": "original (1).zip"}
        capture.__module__ = prepare.__module__ = MODULE
        self.module.trusted_enterprise_context = capture
        self.module.prepare_enterprise_return = prepare
        self.module_patch = patch.dict(sys.modules, {MODULE: self.module})
        self.module_patch.start(); self.addCleanup(self.module_patch.stop)
    def invoke(self, data): return json.loads(asyncio.run(products.handler_for(self.context)(data)))
    def test_schema_has_no_host_path_token_or_arbitrary_source(self):
        products.register_products(self.context)
        tool = self.context.tools["filebrowser_product_materials"]
        self.assertTrue(tool["is_async"])
        self.assertFalse(tool["override"])
        props = tool["schema"]["parameters"]["properties"]
        self.assertFalse({"source", "token", "url", "local_path"} & props.keys())
        self.assertEqual(self.context.tools["filebrowser_ingest_product_zip"]["schema"]["parameters"]["required"], ["attachment_id"])
    def test_identity_profile_chat_mismatch_has_no_file_effect(self):
        for key in products._BINDING_FIELDS:
            with self.subTest(key=key), patch.object(products, "_client") as run:
                row = self.context.values["product_allowed_bindings"][0]
                old=row[key];row[key]="wrong"
                self.assertFalse(self.invoke({"action":"list"})["ok"])
                run.assert_not_called();row[key]=old
    def test_task_expiry_and_scope_are_checked_before_client(self):
        for args in ({"action":"list", "path":"/outside"}, {"action":"list", "path":"/materials/../outside"},
                     {"action":"list", "source":"other"}):
            with patch.object(products,"_client") as run:
                self.assertFalse(self.invoke(args)["ok"]);run.assert_not_called()
        self.active=False
        with patch.object(products,"_client") as run:
            self.assertFalse(self.invoke({"action":"list"})["ok"]);run.assert_not_called()
    def test_export_uses_current_binding_and_opaque_preparation(self):
        response={"schema_version":"filebrowser-agentctl/v1","command":"product-export","ok":True,
                  "result":{"source":"enterprise","path":"/materials/exports/12/original (1).zip","name":"original (1).zip",
                            "mime_type":"application/zip","size_bytes":1234,"sha256":"a"*64,"manifest":[]}}
        with patch.object(products,"_client",return_value=response) as run:
            result=self.invoke({"action":"export","path":"/materials/products/p/v1","categories":["main"],"name":"original (1).zip"})
        self.assertTrue(result["ok"])
        self.assertEqual(run.call_args.args[2]["product"]["destination"],"/materials/exports/12")
        self.assertEqual(self.calls[0]["binding"],BINDING)
        self.assertEqual(result["result"]["return_preparation"]["file_ref"],"enterprise-current-only")
        self.assertFalse(result["result"]["delivery_confirmed"])
    def test_expiry_after_export_does_not_mint_return_reference(self):
        def expired(*args,**kwargs): self.active=False;return {"ok":True,"result":{}}
        with patch.object(products,"_client",side_effect=expired):
            self.assertFalse(self.invoke({"action":"export","path":"/materials/p","categories":["main"],"name":"x.zip"})["ok"])
        self.assertFalse(self.calls)
    def test_organize_uses_current_operation_and_fixed_recovery_scope(self):
        with patch.object(products,"_client",return_value={"ok":True,"result":{"state":"complete"}}) as run:
            result=self.invoke({"action":"move","path":"/materials/a.jpg","destination":"/materials/b.jpg","expected_sha256":"a"*64})
        self.assertTrue(result["ok"])
        self.assertEqual(run.call_args.args[1],"product-organize")
        self.assertEqual(run.call_args.args[2]["product"]["recovery_root"],"/materials/.recovery")
        self.assertTrue(run.call_args.args[2]["operation_id"].startswith("product-12-"))
        self.assertTrue(run.call_args.kwargs["apply"])
        for key in ("destination","replacement_path","recovery_path"):
            with patch.object(products,"_client") as run:
                result=self.invoke({"action":"copy","path":"/materials/a.jpg",key:"/outside"})
                self.assertFalse(result["ok"]);run.assert_not_called()

    def test_timeout_is_outcome_unknown_not_safe_retry(self):
        import subprocess
        with patch.object(products,"_client",side_effect=subprocess.TimeoutExpired("client",180)):
            result=self.invoke({"action":"import","path":"/materials/incoming/x.zip"})
        self.assertIn("outcome_unknown",result["error"]["code"])

if __name__ == "__main__": unittest.main()
