#!/usr/bin/env python3
"""Real HTTPS acceptance against an isolated fixed-image FileBrowser deployment.

No response bodies or credentials are printed. The state file is sensitive and
must travel only between the isolated guest clients, never to CI artifacts.
API contracts come from backend/http handlers and their security regression tests.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import struct
import sys
import urllib.parse
import zipfile
import zlib

SOURCE = "enterprise-files"
PERMISSIONS = ("api", "admin", "browse", "preview", "download", "create", "modify", "delete", "share", "realtime")
DENIED = (401, 403, 404)
ROOT = Path(__file__).resolve().parents[2]


class AcceptanceError(RuntimeError):
    pass


class Reply:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def json(self):
        try:
            return json.loads(self.body)
        except (ValueError, UnicodeError) as error:
            raise AcceptanceError("response was not the required JSON type; body suppressed") from error


class Client:
    def __init__(self, url, ca_file):
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".test")
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ("", "/") or parsed.port != 18443):
            raise AcceptanceError("use the isolated .test HTTPS host on port 18443, without URL credentials")
        self.host, self.port = parsed.hostname, parsed.port
        self.context = ssl.create_default_context(cafile=str(ca_file))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.requests = 0

    def request(self, method, endpoint, *, token=None, query=None, data=None, body=None, headers=None):
        if not endpoint.startswith("/api/") and not endpoint.startswith("/public/api/") and endpoint != "/health":
            raise AcceptanceError("unexpected API endpoint")
        if query and any(key.lower() in ("auth", "token", "password") for key in query):
            raise AcceptanceError("authentication secrets must be sent only in headers")
        path = endpoint + (("?" + urllib.parse.urlencode(query, doseq=True)) if query else "")
        outgoing = {"Accept": "application/json", "Connection": "close", **(headers or {})}
        if token:
            outgoing["Authorization"] = "Bearer " + token
        if data is not None:
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            outgoing["Content-Type"] = "application/json"
        elif body is not None:
            outgoing["Content-Type"] = "application/octet-stream"
        connection = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=90)
        try:
            self.requests += 1
            connection.request(method, path, body=body, headers=outgoing)
            response = connection.getresponse()
            raw = response.read(32 * 1024 * 1024 + 1)
            if len(raw) > 32 * 1024 * 1024:
                raise AcceptanceError("response exceeded the acceptance size limit")
            return Reply(response.status, {k.lower(): v for k, v in response.getheaders()}, raw)
        except (OSError, http.client.HTTPException) as error:
            # Never stringify an exception that may contain a URL, header or body.
            raise AcceptanceError("TLS or HTTP transport failed; diagnostics suppressed") from error
        finally:
            connection.close()


def protected_path(path, *, existing=True, secret=False):
    path = Path(path)
    if not path.is_absolute():
        raise AcceptanceError("protected file paths must be absolute")
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise AcceptanceError("protected file parents must be root-owned and not group/other writable")
    if existing:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1
                or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022):
            raise AcceptanceError("protected input must be a root-owned regular file")
        if secret and stat.S_IMODE(info.st_mode) not in (0o400, 0o600):
            raise AcceptanceError("sensitive input must have mode 0400 or 0600")
    elif path.exists() or path.is_symlink():
        raise AcceptanceError("output already exists; preserve it and choose a new path")
    return path


def write_json(path, value, *, replace=False):
    if replace:
        protected_path(path, secret=True)
    else:
        protected_path(path, existing=False)
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    temporary = path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if replace:
        os.replace(temporary, path)
    else:
        os.link(temporary, path)
        temporary.unlink()


def permissions(**changes):
    result = {name: name not in ("admin", "realtime") for name in PERMISSIONS}
    result.update(changes)
    return result


def png_fixture():
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
    # Deterministic high-entropy 512x512 PNG exceeds the original-image shortcut.
    pixels = b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(24576))
    rows = b"".join(b"\0" + pixels[y * 1536:(y + 1) * 1536] for y in range(512))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 512, 512, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")


def pdf_fixture():
    content = b"BT /F1 18 Tf 30 80 Td (FileBrowser isolated acceptance) Tj ET\n"
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 140] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
               b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"endstream"]
    data, offsets = b"%PDF-1.4\n", [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(data))
        data += str(number).encode() + b" 0 obj\n" + obj + b"\nendobj\n"
    xref = len(data)
    data += b"xref\n0 6\n0000000000 65535 f \n"
    data += b"".join(f"{offset:010} 00000 n \n".encode() for offset in offsets[1:])
    return data + b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n" + str(xref).encode() + b"\n%%EOF\n"


def spreadsheet_fixture():
    entries = {
        "[Content_Types].xml": '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>',
        "_rels/.rels": '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
        "xl/workbook.xml": '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Acceptance" sheetId="1" r:id="rId1"/></sheets></workbook>',
        "xl/_rels/workbook.xml.rels": '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
        "xl/worksheets/sheet1.xml": '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Isolated acceptance</t></is></c><c r="B1"><v>42</v></c></row></sheetData></worksheet>',
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for name, content in entries.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            package.writestr(info, '<?xml version="1.0" encoding="UTF-8"?>' + content)
    return output.getvalue()


def fixtures():
    jpeg = (ROOT / "frontend/tests/playwright-files/myfolder/testdata/gray-sample.jpg").read_bytes()
    spreadsheet = spreadsheet_fixture()
    if not jpeg.startswith(b"\xff\xd8") or not zipfile.is_zipfile(io.BytesIO(spreadsheet)):
        raise AcceptanceError("JPEG or spreadsheet fixture is invalid")
    return {"中文 空格.txt": "隔离环境字节一致性\nFileBrowser acceptance\n".encode(),
            "empty.txt": b"", "large-8MiB.bin": bytes(range(256)) * 32768,
            "document.pdf": pdf_fixture(), "spreadsheet.xlsx": spreadsheet,
            "picture.png": png_fixture(), "photo.jpg": jpeg}


class Acceptance:
    def __init__(self, client, args, state):
        self.client, self.args, self.state = client, args, state
        self.checks, self.incomplete = [], []
        self.preview = {}
        self.admin_password = protected_path(args.admin_password_file, secret=True).read_text(encoding="utf-8")
        if self.admin_password.endswith("\n"):
            self.admin_password = self.admin_password[:-1]
        if not 24 <= len(self.admin_password) <= 4096 or any(c in self.admin_password for c in "\r\n\0"):
            raise AcceptanceError("administrator password input has invalid shape")
        self.admin = None

    def check(self, label, condition, **details):
        self.checks.append({"check": label, "passed": bool(condition), **details})
        if not condition:
            raise AcceptanceError(label)

    def expect(self, label, reply, statuses=(200,)):
        self.check(label, reply.status in statuses, http_status=reply.status)
        return reply

    def request(self, label, method, endpoint, *, statuses=(200,), **kwargs):
        return self.expect(label, self.client.request(method, endpoint, **kwargs), statuses)

    def checkpoint(self):
        write_json(Path(self.args.state_file), self.state, replace=True)

    def login(self, username, password, label):
        reply = self.request(label, "POST", "/api/auth/login", query={"username": username},
                             headers={"X-Password": urllib.parse.quote(password, safe="")})
        token = reply.body.decode("ascii").strip()
        self.check(label + "_session_shape", token.count(".") == 2 and len(token) > 40)
        return token

    def login_admin(self):
        self.admin = self.login("admin", self.admin_password, "administrator_login")
        who = self.request("administrator_identity", "GET", "/api/users", token=self.admin, query={"id": "self"}).json()
        self.check("administrator_privilege", who.get("username") == "admin" and who.get("permissions", {}).get("admin") is True)

    def resource(self, label, method, path, token, *, data=None, body=None, statuses=(200,), **query):
        return self.request(label, method, "/api/resources", token=token, query={"source": SOURCE, "path": path, **query}, data=data, body=body, statuses=statuses)

    def download(self, label, path, token, *, statuses=(200,)):
        return self.request(label, "GET", "/api/resources/download", token=token, query={"source": SOURCE, "file": path}, statuses=statuses)

    def preview_request(self, label, path, token, *, statuses=(200,), size="small"):
        return self.request(label, "GET", "/api/resources/preview", token=token,
                            query={"source": SOURCE, "path": path, "size": size}, statuses=statuses)

    def create_user(self, role, granted):
        account = {"username": "accept_" + role + "_" + self.state["id"], "password": secrets.token_urlsafe(32),
                   "permissions": granted, "loginMethod": "password", "locale": "en",
                   "scopes": [{"name": SOURCE, "scope": self.state["root"]}]}
        self.state["users"][role] = account
        self.checkpoint()
        self.request(role + "_create", "POST", "/api/users", token=self.admin,
                     headers={"X-Password": urllib.parse.quote(self.admin_password, safe="")},
                     data={"which": [], "data": account}, statuses=(201,))
        listing = self.request(role + "_lookup", "GET", "/api/users", token=self.admin).json()
        matches = [user for user in listing if user.get("username") == account["username"]]
        self.check(role + "_created_once", len(matches) == 1)
        account["id"] = matches[0]["id"]
        self.checkpoint()
        token = self.login(account["username"], account["password"], role + "_login")
        self.check(role + "_ordinary_identity", matches[0].get("permissions", {}).get("admin") is False)
        return token

    def set_permissions(self, role, granted):
        account = self.state["users"][role]
        self.request(role + "_permissions_update", "PUT", "/api/users", token=self.admin,
                     query={"id": account["id"]}, data={"which": ["permissions"], "data": {"permissions": granted}},
                     headers={"X-Password": urllib.parse.quote(self.admin_password, safe="")})
        account["permissions"] = granted
        self.checkpoint()

    def remember_file(self, relative, content):
        self.state["files"][relative] = {"sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
        self.checkpoint()

    def check_bytes(self, label, content, expected):
        self.check(label, len(content) == expected["size"] and hashlib.sha256(content).hexdigest() == expected["sha256"], size=len(content), sha256=hashlib.sha256(content).hexdigest())

    def create_token(self, role, session, name, grants):
        result = self.request(name + "_issue", "POST", "/api/auth/token", token=session,
                              query={"name": self.state["id"] + "-" + name, "days": "7", "permissions": grants, "minimal": "false"}).json()
        secret = result.get("token")
        self.check(name + "_token_returned", isinstance(secret, str) and len(secret) > 40)
        self.state["tokens"][name] = {"value": secret, "name": self.state["id"] + "-" + name, "role": role}
        self.checkpoint()
        return secret

    def public(self, label, path, share, *, statuses=(200,), password=None, method="GET", body=None, endpoint="resources/download"):
        query = {"hash": share["hash"], "file" if endpoint.endswith("download") else "path": path}
        headers = {"X-SHARE-PASSWORD": password} if password else {}
        return self.request(label, method, "/public/api/" + endpoint, query=query, headers=headers, body=body, statuses=statuses)

    def share_payload(self, **changes):
        return {"source": SOURCE, "path": "/", "shareType": "normal", "title": "Isolated acceptance",
                "disableDownload": False, "disableThumbnails": False, "disableFileViewer": False,
                "allowCreate": False, "allowModify": False, "allowDelete": False,
                "allowReplacements": False, **changes}

    def save_share(self, key, session, payload):
        result = self.request(key + "_share_save", "POST", "/api/share", token=session, data=payload).json()
        self.check(key + "_share_hash", isinstance(result.get("hash"), str) and bool(result["hash"]))
        self.check(key + "_share_redaction", "password_hash" not in result and "passwordHash" not in result and "token" not in result)
        self.state["shares"][key] = {"hash": result["hash"], "password": payload.get("password"), "has_password": result.get("hasPassword", False)}
        self.checkpoint()
        return self.state["shares"][key]

    def check_audit(self, session):
        self.request("ordinary_audit_query_denied", "GET", "/api/audit", token=session, statuses=(403,))
        items = []
        cursor = None
        for _ in range(20):
            query = {"actor": self.state["users"]["worker"]["username"], "limit": "100"}
            if cursor:
                query["cursor"] = cursor
            result = self.request("administrator_audit_query", "GET", "/api/audit", token=self.admin, query=query).json()
            self.check("audit_page_shape", isinstance(result.get("items"), list))
            items.extend(result["items"])
            if not result.get("hasMore"):
                break
            cursor = result.get("nextCursor")
            self.check("audit_cursor_available", isinstance(cursor, str) and bool(cursor))
        actions = {event.get("action") for event in items}
        self.check("audit_has_write_evidence", "file.upload" in actions and "file.modify" in actions and "file.delete" in actions)
        serialized = json.dumps(items)
        sensitive = [self.admin_password] + [a["password"] for a in self.state["users"].values()]
        sensitive += [t["value"] for t in self.state["tokens"].values()]
        sensitive += [s["hash"] for s in self.state["shares"].values()]
        sensitive += [s["password"] for s in self.state["shares"].values() if s.get("password")]
        self.check("audit_credentials_redacted", all(secret not in serialized for secret in sensitive))
        ids = {event["requestId"] for event in items}
        if "audit_ids" in self.state:
            self.check("audit_persisted_across_restore", set(self.state["audit_ids"]).issubset(ids))
        else:
            self.state["audit_ids"] = sorted(ids)
            self.checkpoint()
        self.check("audit_records_present", len(ids) > 0, record_count=len(ids))
    def exercise(self):
        self.login_admin()
        self.resource("fixture_directory_create", "POST", self.state["root"], self.admin, isDir="true", body=b"")
        worker = self.create_user("worker", permissions())
        reader = self.create_user("reader", permissions(create=False, modify=False, delete=False))
        stranger = self.create_user("stranger", permissions(create=False, modify=False, delete=False))
        self.create_user("ui", permissions(api=False, share=False))
        self.state["ui"] = {key: self.state["users"]["ui"][key] for key in ("username", "password")}
        self.checkpoint()
        source_info = self.request("source_configuration", "GET", "/api/settings", token=self.admin, query={"property": "sources"}).json()
        sources = [source for source in source_info if source.get("name") == SOURCE]
        self.check("dedicated_source_present", len(sources) == 1)
        share_enabled = sources[0].get("config", {}).get("private") is False
        self.state["share_enabled"] = share_enabled
        self.checkpoint()
        originals = fixtures()
        for name, raw in originals.items():
            self.resource("upload_" + name.split(".")[-1], "POST", "/" + name, worker, body=raw)
            self.remember_file(name, raw)
            result = self.download("download_byte_roundtrip", "/" + name, worker)
            self.check_bytes("byte_roundtrip_" + name.split(".")[-1], result.body, self.state["files"][name])
        viewed = self.resource("text_viewer_content", "GET", "/中文 空格.txt", worker, content="true").json()
        self.check("text_viewer_exact_content", viewed.get("content") == originals["中文 空格.txt"].decode("utf-8"))
        self.resource("ordinary_browse_allowed", "GET", "/", worker)
        self.set_permissions("worker", permissions(browse=False))
        self.resource("ordinary_browse_denied", "GET", "/", worker, statuses=(403,))
        self.download("browse_required_for_download", "/中文 空格.txt", worker, statuses=(403,))
        self.preview_request("browse_required_for_preview", "/picture.png", worker, statuses=(403,))
        self.set_permissions("worker", permissions(preview=False))
        self.preview_request("ordinary_preview_denied", "/picture.png", worker, statuses=(403,))
        self.download("download_independent_of_preview", "/picture.png", worker)
        self.set_permissions("worker", permissions(download=False))
        derived = self.preview_request("preview_allowed_without_download", "/picture.png", worker)
        self.check("derived_preview_not_original", bool(derived.body) and derived.body != originals["picture.png"] and derived.headers.get("content-type", "").startswith("image/"))
        self.download("ordinary_download_denied", "/中文 空格.txt", worker, statuses=(403,))
        self.resource("text_viewer_requires_download", "GET", "/中文 空格.txt", worker, content="true", statuses=(403,))
        self.preview_request("original_preview_requires_download", "/picture.png", worker, statuses=(403,), size="original")
        self.set_permissions("worker", permissions())
        for name in ("中文 空格.txt", "document.pdf", "spreadsheet.xlsx", "picture.png", "photo.jpg"):
            metadata = self.resource("preview_metadata", "GET", "/" + name, worker).json()
            advertised = metadata.get("hasPreview") is True
            response = self.client.request("GET", "/api/resources/preview", token=worker, query={"source": SOURCE, "path": "/" + name, "size": "small"})
            kind = name.split(".")[-1]
            if response.status == 200 and response.body and response.headers.get("content-type", "").startswith("image/"):
                self.preview[kind] = {"advertised": advertised, "observed": "image_preview", "sha256": hashlib.sha256(response.body).hexdigest()}
                self.check("actual_preview_" + kind, True)
            elif not advertised and response.status in (400, 501):
                self.preview[kind] = {"advertised": False, "observed": "no_server_image_preview", "http_status": response.status}
                self.check("preview_capability_report_" + kind, True)
            else:
                self.preview[kind] = {"advertised": advertised, "observed": "unavailable", "http_status": response.status}
                self.incomplete.append("actual_preview_" + kind)
        self.state["preview_observations"] = self.preview
        self.checkpoint()
        self.write_permission_matrix(worker)
        self.archive_tests(worker)
        self.token_tests(worker, reader)
        if share_enabled:
            self.share_tests(worker, reader, stranger)
        else:
            self.request("private_source_blocks_share", "POST", "/api/share", token=reader, data=self.share_payload(), statuses=(403,))
            self.incomplete.append("positive_share_requires_explicit_enable_share_source")
        # Persist an account-level withdrawal against a still-valid API token and
        # a share. UI has a separate ordinary account with its original grants.
        self.set_permissions("worker", permissions(download=False))
        self.download("session_permission_withdrawal_immediate", "/中文 空格.txt", worker, statuses=(403,))
        self.download("token_permission_withdrawal_immediate", "/中文 空格.txt", self.state["tokens"]["ceiling"]["value"], statuses=(403,))
        if "owner_withdrawn" in self.state["shares"]:
            self.public("share_owner_withdrawal_immediate", "/中文 空格.txt", self.state["shares"]["owner_withdrawn"], statuses=DENIED)
        self.check_audit(worker)
        self.state["seed_completed"] = not self.incomplete
        self.checkpoint()

    def write_permission_matrix(self, worker):
        for method in ("POST", "PUT"):
            name = "/rights-" + method.lower() + ".txt"
            self.set_permissions("worker", permissions(create=False, modify=False))
            self.resource(method + "_new_denied_without_create", method, name, worker, body=b"blocked", statuses=(403,))
            self.resource(method + "_new_not_written", "GET", name, worker, statuses=(404,))
            self.set_permissions("worker", permissions(modify=False))
            self.resource(method + "_new_allowed_with_create", method, name, worker, body=b"original")
            self.resource(method + "_overwrite_denied_without_modify", method, name, worker, body=b"must-not-overwrite", override="true", statuses=(403,))
            self.check(method + "_denied_overwrite_preserves_bytes", self.download("rights_download", name, worker).body == b"original")
            self.set_permissions("worker", permissions(create=False))
            self.resource(method + "_overwrite_allowed_modify_only", method, name, worker, body=b"modified", override="true")
            self.check(method + "_overwrite_committed", self.download("rights_download", name, worker).body == b"modified")
            self.resource(method + "_modify_cannot_create", method, name + ".new", worker, body=b"blocked", statuses=(403,))
        self.set_permissions("worker", permissions())
        self.resource("mkdir_move_destination", "POST", "/moved", worker, isDir="true", body=b"")
        self.resource("rename_fixture", "POST", "/rename-before.txt", worker, body=b"rename-move-delete")
        for action, source, target in (("rename", "/rename-before.txt", "/rename-after.txt"), ("move", "/rename-after.txt", "/moved/result.txt")):
            result = self.request(action + "_allowed", "PATCH", "/api/resources", token=worker,
                                  data={"action": action, "overwrite": False, "rename": False,
                                        "items": [{"fromSource": SOURCE, "fromPath": source, "toSource": SOURCE, "toPath": target}]}).json()
            self.check(action + "_all_items_succeeded", len(result.get("succeeded", [])) == 1 and not result.get("failed"))
            self.resource(action + "_source_absent", "GET", source, worker, statuses=(404,))
        self.check("move_preserves_bytes", self.download("moved_download", "/moved/result.txt", worker).body == b"rename-move-delete")
        self.set_permissions("worker", permissions(delete=False))
        self.resource("delete_permission_denied", "DELETE", "/moved/result.txt", worker, statuses=(403,))
        self.set_permissions("worker", permissions())
        self.resource("delete_allowed", "DELETE", "/moved/result.txt", worker)
        self.resource("deleted_file_absent", "GET", "/moved/result.txt", worker, statuses=(404,))
        self.resource("authenticated_path_traversal_denied", "GET", "/../outside", worker, statuses=(400, 403, 404))
        self.request("ordinary_cannot_escalate_admin", "PUT", "/api/users", token=worker,
                     query={"id": self.state["users"]["worker"]["id"]},
                     data={"which": ["permissions"], "data": {"permissions": permissions(admin=True)}}, statuses=(403,))

    def archive_tests(self, worker):
        request = {"fromSource": SOURCE, "paths": ["/中文 空格.txt", "/empty.txt"], "destination": "/safe.zip", "format": "zip"}
        self.request("archive_create_allowed", "POST", "/api/resources/archive", token=worker, data=request)
        result = self.download("archive_download_allowed", "/safe.zip", worker)
        with zipfile.ZipFile(io.BytesIO(result.body)) as package:
            names = package.namelist()
            self.check("generated_archive_paths_safe", all(not n.startswith("/") and ".." not in n.split("/") and "\\" not in n for n in names))
            self.check("generated_archive_payload_exact", package.read("中文 空格.txt") == fixtures()["中文 空格.txt"] and package.read("empty.txt") == b"")
        self.resource("archive_destination_create", "POST", "/unpacked", worker, isDir="true", body=b"")
        self.request("archive_extract_allowed", "POST", "/api/resources/unarchive", token=worker,
                     data={"fromSource": SOURCE, "path": "/safe.zip", "destination": "/unpacked"})
        self.check_bytes("archive_extraction_byte_integrity", self.download("extracted_download", "/unpacked/中文 空格.txt", worker).body, self.state["files"]["中文 空格.txt"])
        for label, entry, mode in (("traversal", "../archive-escaped.txt", stat.S_IFREG | 0o644),
                                    ("symlink", "redirect", stat.S_IFLNK | 0o777)):
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as package:
                info = zipfile.ZipInfo(entry)
                info.create_system, info.external_attr = 3, mode << 16
                package.writestr(info, "../../archive-escaped.txt" if label == "symlink" else "must not escape")
            self.resource("unsafe_archive_upload", "POST", "/unsafe-" + label + ".zip", worker, body=output.getvalue())
            self.resource("unsafe_archive_destination", "POST", "/extract-" + label, worker, isDir="true", body=b"")
            self.request(label + "_archive_rejected", "POST", "/api/resources/unarchive", token=worker,
                         data={"fromSource": SOURCE, "path": "/unsafe-" + label + ".zip", "destination": "/extract-" + label},
                         statuses=(400, 403, 409, 422, 500))
            self.resource(label + "_archive_no_escaped_write", "GET", "/archive-escaped.txt", worker, statuses=(404,))
        self.set_permissions("worker", permissions(download=False))
        request["destination"] = "/forbidden-download.zip"
        self.request("archive_download_permission_required", "POST", "/api/resources/archive", token=worker, data=request, statuses=(403,))
        self.resource("denied_archive_not_created", "GET", request["destination"], worker, statuses=(404,))
        self.set_permissions("worker", permissions())

    def token_tests(self, worker, reader):
        live = self.create_token("reader", reader, "live", "api,browse,download")
        self.download("live_token_download", "/中文 空格.txt", live)
        self.resource("live_token_cannot_write", "POST", "/token-forbidden.txt", live, body=b"blocked", statuses=(403,))
        overclaimed = self.create_token("reader", reader, "overclaimed", "api,browse,download,create,admin")
        self.resource("token_cannot_exceed_user_create", "POST", "/overclaim-forbidden.txt", overclaimed, body=b"blocked", statuses=(403,))
        self.request("token_cannot_exceed_user_admin", "GET", "/api/audit", token=overclaimed, statuses=(403,))
        narrow = self.create_token("worker", worker, "narrow", "api,browse")
        self.resource("narrow_token_browse", "GET", "/", narrow)
        self.download("token_intersection_denies_download", "/中文 空格.txt", narrow, statuses=(403,))
        self.request("token_cannot_mint_child", "POST", "/api/auth/token", token=narrow,
                     query={"name": self.state["id"] + "-child", "days": "1", "permissions": "api,browse,download"}, statuses=(403,))
        self.create_token("worker", worker, "ceiling", "api,browse,download")
        revoked = self.create_token("reader", reader, "revoked", "api,browse,download")
        self.download("token_before_revoke", "/中文 空格.txt", revoked)
        self.request("token_revoke", "DELETE", "/api/auth/token", token=reader, query={"name": self.state["tokens"]["revoked"]["name"]})
        self.download("revoked_token_immediately_denied", "/中文 空格.txt", revoked, statuses=DENIED)
        listing = self.request("token_list_redacted", "GET", "/api/auth/token/list", token=reader)
        self.check("token_secrets_not_listed", all(token["value"].encode() not in listing.body for token in self.state["tokens"].values()))

    def share_tests(self, worker, reader, stranger):
        self.set_permissions("worker", permissions(share=False))
        self.request("ordinary_share_permission_denied", "POST", "/api/share", token=worker, data=self.share_payload(), statuses=(403,))
        self.set_permissions("worker", permissions())
        password = secrets.token_urlsafe(24)
        active = self.save_share("active", reader, self.share_payload(password=password))
        self.check("share_password_enabled", active["has_password"] is True)
        self.public("password_share_missing_password_denied", "/中文 空格.txt", active, statuses=(401,))
        self.public("password_share_wrong_password_denied", "/中文 空格.txt", active, password="deliberately-wrong-acceptance-password", statuses=(401,))
        self.check_bytes("password_share_byte_integrity", self.public("password_share_download", "/中文 空格.txt", active, password=password).body, self.state["files"]["中文 空格.txt"])
        for label, patch in (("missing_keeps", {}), ("null_keeps", {"password": None})):
            response = self.request("share_password_" + label, "POST", "/api/share", token=reader,
                                    data=self.share_payload(hash=active["hash"], **patch)).json()
            self.check("share_password_state_" + label, response.get("hasPassword") is True)
            self.public("share_password_auth_" + label, "/中文 空格.txt", active, password=password)
        new_password = secrets.token_urlsafe(24)
        self.request("share_password_replace", "POST", "/api/share", token=reader, data=self.share_payload(hash=active["hash"], password=new_password))
        self.public("old_share_password_denied", "/中文 空格.txt", active, password=password, statuses=(401,))
        self.public("new_share_password_accepted", "/中文 空格.txt", active, password=new_password)
        self.request("share_password_remove", "POST", "/api/share", token=reader, data=self.share_payload(hash=active["hash"], password=""))
        self.public("removed_share_password_anonymous_allowed", "/中文 空格.txt", active)
        self.request("restore_password_for_persistence", "POST", "/api/share", token=reader, data=self.share_payload(hash=active["hash"], password=new_password))
        active["password"] = new_password
        self.checkpoint()
        self.public("share_cannot_create", "/share-denied-new.txt", active, password=new_password,
                    endpoint="resources", method="POST", body=b"blocked", statuses=(403,))
        self.public("share_cannot_overwrite", "/中文 空格.txt", active, password=new_password,
                    endpoint="resources", method="PUT", body=b"blocked", statuses=(403,))
        self.public("share_path_escape_denied", "/../outside.txt", active, password=new_password, statuses=(400, 403, 404))
        self.request("nonowner_share_update_denied", "POST", "/api/share", token=stranger,
                     data=self.share_payload(hash=active["hash"], password=""), statuses=(403,))
        self.request("nonowner_share_delete_denied", "DELETE", "/api/share", token=stranger, query={"hash": active["hash"]}, statuses=(403,))
        denied = self.save_share("download_denied", reader, self.share_payload(disableDownload=True))
        self.public("share_download_capability_denied", "/中文 空格.txt", denied, statuses=(403,))
        deleted = self.save_share("deleted", reader, self.share_payload())
        self.public("share_before_delete", "/中文 空格.txt", deleted)
        self.request("share_delete", "DELETE", "/api/share", token=reader, query={"hash": deleted["hash"]})
        self.public("deleted_share_denied", "/中文 空格.txt", deleted, statuses=DENIED)
        writable = self.save_share("writable", worker, self.share_payload(allowCreate=True, allowModify=True, allowDelete=True, allowReplacements=True))
        self.public("share_create_allowed", "/share-write.txt", writable, endpoint="resources", method="POST", body=b"share original")
        self.public("share_modify_allowed", "/share-write.txt", writable, endpoint="resources", method="PUT", body=b"share modified")
        self.check("share_write_bytes_verified", self.public("share_modified_download", "/share-write.txt", writable).body == b"share modified")
        self.public("share_delete_allowed", "/share-write.txt", writable, endpoint="resources", method="DELETE")
        self.resource("share_deleted_file_absent", "GET", "/share-write.txt", worker, statuses=(404,))
        owner = self.save_share("owner_withdrawn", worker, self.share_payload())
        self.public("share_owner_before_withdrawal", "/中文 空格.txt", owner)

    def verify_restored(self):
        self.check("completed_seed_required", self.state.get("seed_completed") is True)
        self.login_admin()
        sessions = {}
        for role, account in self.state["users"].items():
            sessions[role] = self.login(account["username"], account["password"], role + "_restored_login")
            who = self.request(role + "_restored_identity", "GET", "/api/users", token=sessions[role], query={"id": "self"}).json()
            self.check(role + "_permissions_persisted", who.get("permissions") == account["permissions"])
        for name, expected in self.state["files"].items():
            result = self.download("restored_file_download", self.state["root"] + "/" + name, self.admin)
            self.check_bytes("restored_file_byte_integrity", result.body, expected)
        self.download("restored_live_token_download", "/中文 空格.txt", self.state["tokens"]["live"]["value"])
        self.resource("restored_narrow_token_browse", "GET", "/", self.state["tokens"]["narrow"]["value"])
        self.resource("restored_overclaimed_token_still_limited", "POST", "/restore-overclaim-denied.txt", self.state["tokens"]["overclaimed"]["value"], body=b"blocked", statuses=(403,))
        for name in ("revoked", "narrow", "ceiling"):
            self.download("restored_" + name + "_token_denied", "/中文 空格.txt", self.state["tokens"][name]["value"], statuses=DENIED)
        self.download("restored_user_withdrawal_denied", "/中文 空格.txt", sessions["worker"], statuses=(403,))
        if self.state.get("share_enabled"):
            active = self.state["shares"]["active"]
            self.check_bytes("restored_password_share_integrity", self.public("restored_password_share", "/中文 空格.txt", active, password=active["password"]).body, self.state["files"]["中文 空格.txt"])
            self.public("restored_password_still_required", "/中文 空格.txt", active, statuses=(401,))
            for name in ("deleted", "download_denied", "owner_withdrawn"):
                self.public("restored_" + name + "_share_denied", "/中文 空格.txt", self.state["shares"][name], statuses=DENIED)
        self.check_audit(sessions["worker"])
        fresh = "/restored-readwrite-" + secrets.token_hex(8) + ".txt"
        self.resource("restored_actual_create", "POST", fresh, sessions["ui"], body=b"restored write")
        self.resource("restored_actual_modify", "PUT", fresh, sessions["ui"], body=b"restored modify")
        self.check("restored_actual_read", self.download("restored_actual_download", fresh, sessions["ui"]).body == b"restored modify")
        self.resource("restored_actual_delete", "DELETE", fresh, sessions["ui"])
        preview = self.preview_request("restored_actual_preview", "/picture.png", sessions["ui"])
        self.check("restored_preview_has_bytes", bool(preview.body) and preview.headers.get("content-type", "").startswith("image/"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("exercise", "verify-restored"))
    parser.add_argument("--url", "--base-url", dest="url", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--admin-password-file", required=True)
    parser.add_argument("--state-file", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args(argv)
    if sys.platform != "linux" or os.geteuid() != 0:
        raise AcceptanceError("run only as root in the explicitly authorized isolated Linux guest")
    os.umask(0o077)
    ca = protected_path(args.ca_file)
    evidence_path = protected_path(args.evidence, existing=False)
    state_path = Path(args.state_file)
    if args.phase == "exercise":
        protected_path(state_path, existing=False)
        identifier = secrets.token_hex(6)
        state = {"version": 1, "id": identifier, "source": SOURCE, "root": "/cf-acceptance-" + identifier,
                 "users": {}, "files": {}, "tokens": {}, "shares": {}, "seed_completed": False}
        write_json(state_path, state)
    else:
        state = json.loads(protected_path(state_path, secret=True).read_bytes())
        if state.get("version") != 1 or state.get("source") != SOURCE:
            raise AcceptanceError("unsupported protected acceptance state")
    client = Client(args.url, ca)
    test = Acceptance(client, args, state)
    exit_code = 0
    failure = None
    try:
        if args.phase == "exercise":
            test.exercise()
        else:
            test.verify_restored()
        if test.incomplete:
            exit_code = 3
    except (AcceptanceError, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as error:
        exit_code = 1
        failure = str(error) if isinstance(error, AcceptanceError) else type(error).__name__ + "; details suppressed"
    evidence = {"version": 1, "phase": args.phase, "passed": exit_code == 0,
                "requests": client.requests, "checks": test.checks, "incomplete": test.incomplete,
                "preview_observations": test.preview, "failure": failure,
                "existing_go_regression_coverage": ["audit_pending_finalize", "audit_write_precommit_fail_closed"]}
    write_json(evidence_path, evidence)
    print(json.dumps({"phase": args.phase, "passed": exit_code == 0, "request_count": client.requests,
                      "check_count": len(test.checks), "incomplete_count": len(test.incomplete), "failure": failure}, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, OSError, ValueError, KeyError) as error:
        message = str(error) if isinstance(error, AcceptanceError) else type(error).__name__ + "; details suppressed"
        print(json.dumps({"passed": False, "configuration_error": message}, sort_keys=True))
        raise SystemExit(2)