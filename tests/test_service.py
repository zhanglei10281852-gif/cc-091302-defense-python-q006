"""文档分级流转服务测试 —— 覆盖需求中的每条硬性约束。"""

import base64
import glob
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from threading import Thread

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.service import DocumentFlowService, ServiceError, make_handler  # noqa: E402


class FlowTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.clock_now = 1_700_000_000.0
        self.svc = DocumentFlowService(
            self.tmp, clock=lambda: self.clock_now)

    def tearDown(self):
        self.svc.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def advance(self, seconds):
        self.clock_now += seconds
        return self.clock_now


class TestDocumentsAndDedup(FlowTestBase):
    def test_create_and_dedup_same_content(self):
        r1 = self.svc.create_document("简报A", b"hello", "alice")
        self.assertFalse(r1["dedup"])
        doc_id = r1["document"]["document_id"]

        # 完全相同内容重复上传 → 识别为已有版本 v1
        r2 = self.svc.add_version(doc_id, b"hello", "bob")
        self.assertTrue(r2["dedup"])
        self.assertEqual(r2["version"], 1)
        self.assertEqual(len(r2["document"]["versions"]), 1)

        # 不同内容 → 新版本
        r3 = self.svc.add_version(doc_id, b"hello v2", "bob")
        self.assertFalse(r3["dedup"])
        self.assertEqual(r3["version"], 2)

        # 同一内容在新文档中上传也复用 blob（存储去重）
        r4 = self.svc.create_document("简报B", b"hello", "carol")
        self.assertEqual(
            r4["document"]["versions"][0]["content_hash"],
            r1["document"]["versions"][0]["content_hash"])
        self.assertEqual(len(glob.glob(os.path.join(self.tmp, "blobs", "*"))), 2)

    def test_manifest_never_leaks_content(self):
        r = self.svc.create_document("密件", b"TOP-SECRET-BODY", "alice")
        doc_id = r["document"]["document_id"]
        self.svc.add_version(doc_id, b"other body", "alice")
        for dump in (json.dumps(self.svc.export_manifest(), ensure_ascii=False),
                     json.dumps(self.svc.get_document(doc_id), ensure_ascii=False)):
            self.assertNotIn("TOP-SECRET-BODY", dump)
            self.assertNotIn("other body", dump)
        # 清单仅含哈希指纹
        entry = self.svc.export_manifest()["documents"][0]
        self.assertTrue(entry["versions"][0]["content_hash"])

    def test_empty_content_rejected(self):
        with self.assertRaises(ServiceError):
            self.svc.create_document("x", b"", "alice")


class TestClassificationChain(FlowTestBase):
    def prepare(self, initial="内部"):
        r = self.svc.create_document("简报", b"body", "alice",
                                     initial_level=initial)
        return r["document"]["document_id"]

    def test_change_must_be_level_by_level(self):
        doc_id = self.prepare()
        # 内部(2) → 机密(4) 需两节点：秘密审批人、机密审批人
        req = self.svc.request_change(doc_id, "机密", "任务需要", "alice")
        self.assertEqual(req["status"], "pending")
        self.assertEqual(req["pending_node"]["level"]["name"], "秘密")
        self.assertEqual(req["pending_node"]["step_index"], 1)
        rid = req["request_id"]

        # 审批未完成：密级仍为内部
        self.assertEqual(self.svc.get_document(doc_id)["current_level"]["name"], "内部")

        # 非当前节点审批人不能审批
        with self.assertRaises(ServiceError) as cm:
            self.svc.approve_change(rid, "sec-topsecret")
        self.assertEqual(cm.exception.status, 403)

        self.svc.approve_change(rid, "sec-secret")
        self.assertEqual(self.svc.get_document(doc_id)["current_level"]["name"], "内部")
        node = self.svc.get_change_request(rid)["pending_node"]["level"]["name"]
        self.assertEqual(node, "机密")

        self.svc.approve_change(rid, "sec-topsecret")
        self.assertEqual(self.svc.get_document(doc_id)["current_level"]["name"], "机密")
        self.assertIsNone(self.svc.get_document(doc_id)["pending_node"])

    def test_downgrade_chain(self):
        doc_id = self.prepare(initial="机密")
        req = self.svc.request_change(doc_id, "内部", "任务结束降密", "alice")
        rid = req["request_id"]
        # 降级 机密→内部：机密审批人先释放(4→3)，再秘密审批人释放(3→2)
        self.assertEqual(req["pending_node"]["level"]["name"], "机密")
        self.svc.approve_change(rid, "sec-topsecret")
        self.assertEqual(
            self.svc.get_change_request(rid)["pending_node"]["level"]["name"], "秘密")
        # 审批中旧权限不变
        self.assertEqual(self.svc.get_document(doc_id)["current_level"]["name"], "机密")
        self.svc.approve_change(rid, "sec-secret")
        self.assertEqual(self.svc.get_document(doc_id)["current_level"]["name"], "内部")

    def test_reject_requires_reason_and_keeps_old_level(self):
        doc_id = self.prepare()
        req = self.svc.request_change(doc_id, "秘密", "理由不足的申请", "alice")
        rid = req["request_id"]
        with self.assertRaises(ServiceError):
            self.svc.reject_change(rid, "sec-secret", "  ")

        self.svc.reject_change(rid, "sec-secret", "密级依据不充分，缺少定密审批表")
        view = self.svc.get_document(doc_id)
        self.assertEqual(view["current_level"]["name"], "内部")
        self.assertIsNone(view["pending_node"])
        self.assertEqual(view["rejection_reason"]["reason"],
                         "密级依据不充分，缺少定密审批表")
        self.assertEqual(view["rejection_reason"]["rejected_by"], "sec-secret")

    def test_cancel_and_no_parallel_requests(self):
        doc_id = self.prepare()
        rid = self.svc.request_change(doc_id, "秘密", "r", "alice")["request_id"]
        with self.assertRaises(ServiceError) as cm:
            self.svc.request_change(doc_id, "机密", "r2", "alice")
        self.assertEqual(cm.exception.code, "REQUEST_ALREADY_OPEN")
        self.svc.cancel_change(rid, "alice")
        # 结案后可重新申请
        rid2 = self.svc.request_change(doc_id, "秘密", "r3", "alice")["request_id"]
        self.assertEqual(
            self.svc.get_change_request(rid2)["pending_node"]["level"]["name"], "秘密")

    def test_same_level_rejected(self):
        doc_id = self.prepare()
        with self.assertRaises(ServiceError):
            self.svc.request_change(doc_id, "内部", "x", "alice")


class TestScopeRevocationExpiry(FlowTestBase):
    def prepare(self):
        doc_id = self.svc.create_document("简报", b"body", "alice",
                                          initial_level="内部")["document"]["document_id"]
        return doc_id

    def test_grant_download_revoke_immediate(self):
        doc_id = self.prepare()
        self.svc.grant(doc_id, "user:bob", "alice")

        d = self.svc.download(doc_id, "bob")
        self.assertIn("密级:内部", d["watermark"]["text"])
        self.assertTrue(d["watermark"]["watermark_id"])

        self.svc.revoke(doc_id, "user:bob", "alice")
        with self.assertRaises(ServiceError) as cm:
            self.svc.download(doc_id, "bob")
        self.assertEqual(cm.exception.code, "AUTH_REVOKED")
        self.assertEqual(cm.exception.status, 403)

        # 拒绝访问也留痕，且不含正文
        events = self.svc.list_events(doc_id)["events"]
        denied = [e for e in events if e["type"] == "access_denied"]
        self.assertEqual(len(denied), 1)
        self.assertNotIn("content", json.dumps(denied))

    def test_dept_scope(self):
        doc_id = self.prepare()
        self.svc.grant(doc_id, "dept:ops", "alice")
        # 无个人授权、带部门
        self.svc.download(doc_id, "bob", dept="ops")
        with self.assertRaises(ServiceError):
            self.svc.download(doc_id, "bob", dept="hr")
        with self.assertRaises(ServiceError):
            self.svc.download(doc_id, "bob")

    def test_expiry_window(self):
        doc_id = self.prepare()
        self.svc.grant(doc_id, "user:bob", "alice", expires_at=self.clock_now + 100)
        self.svc.download(doc_id, "bob")
        self.advance(99)
        self.svc.download(doc_id, "bob")
        self.advance(2)
        with self.assertRaises(ServiceError) as cm:
            self.svc.download(doc_id, "bob")
        self.assertEqual(cm.exception.code, "AUTH_EXPIRED")

    def test_regrant_after_revoke(self):
        doc_id = self.prepare()
        self.svc.grant(doc_id, "user:bob", "alice")
        self.svc.revoke(doc_id, "user:bob", "alice")
        with self.assertRaises(ServiceError):
            self.svc.download(doc_id, "bob")
        self.svc.grant(doc_id, "user:bob", "alice")
        self.svc.download(doc_id, "bob")

    def test_revocation_preserves_audit_history(self):
        doc_id = self.prepare()
        self.svc.grant(doc_id, "user:bob", "alice")
        self.svc.download(doc_id, "bob")
        self.svc.revoke(doc_id, "user:bob", "alice")
        with self.assertRaises(ServiceError):
            self.svc.download(doc_id, "bob")
        types = [e["type"] for e in self.svc.read_audit_log()["events"]]
        for expected in ("access_granted", "download", "access_revoked", "access_denied"):
            self.assertIn(expected, types)
        # 文档视图中撤销记录仍可见（不抹历史）
        scope = [s for s in self.svc.get_document(doc_id)["visible_scope"]
                 if s["subject"] == "user:bob"][0]
        self.assertEqual(scope["status"], "revoked")
        self.assertEqual(scope["revoked_by"], "alice")


class TestWatermarkAndVersions(FlowTestBase):
    def test_watermark_identity_and_old_version_served_with_old_permission(self):
        doc_id = self.svc.create_document("简报", b"v1-body", "alice")["document"]["document_id"]
        self.svc.grant(doc_id, "user:bob", "alice")
        self.advance(10)
        self.svc.add_version(doc_id, b"v2-body", "alice")

        d2 = self.svc.download(doc_id, "bob")
        self.assertEqual(base64.b64decode(d2["content_base64"]), b"v2-body")
        self.assertEqual(d2["watermark"]["version"], 2)
        self.assertEqual(d2["watermark"]["user"], "bob")

        d1 = self.svc.download(doc_id, "bob", version=1)
        self.assertEqual(base64.b64decode(d1["content_base64"]), b"v1-body")
        self.assertEqual(d1["watermark"]["version"], 1)
        self.assertNotEqual(d1["watermark"]["watermark_id"], d2["watermark"]["watermark_id"])

    def test_level_change_takes_effect_on_watermark_only_after_approval(self):
        doc_id = self.svc.create_document("简报", b"b", "alice",
                                          initial_level="内部")["document"]["document_id"]
        self.svc.grant(doc_id, "user:bob", "alice")
        rid = self.svc.request_change(doc_id, "秘密", "升级", "alice")["request_id"]
        # 审批中水印仍为旧密级
        self.assertIn("密级:内部", self.svc.download(doc_id, "bob")["watermark"]["text"])
        self.svc.approve_change(rid, "sec-secret")
        self.assertIn("密级:秘密", self.svc.download(doc_id, "bob")["watermark"]["text"])


class TestRecovery(FlowTestBase):
    def test_restart_preserves_queue_grants_events(self):
        doc_id = self.svc.create_document("简报", b"body", "alice")["document"]["document_id"]
        self.svc.grant(doc_id, "user:bob", "alice", expires_at=self.clock_now + 500)
        rid = self.svc.request_change(doc_id, "秘密", "升级", "alice")["request_id"]
        self.svc.approve_change  # noqa: B018 (queue still pending)
        self.svc.download(doc_id, "bob")
        events_before = self.svc.list_events()["events"]

        # 重启：同一数据目录新实例，时钟一致
        svc2 = DocumentFlowService(self.tmp, clock=lambda: self.clock_now)
        doc_view = svc2.get_document(doc_id)
        self.assertEqual(doc_view["current_level"]["name"], "内部")
        self.assertEqual(doc_view["pending_node"]["request_id"], rid)
        self.assertEqual(doc_view["pending_node"]["level"]["name"], "秘密")
        bob = [s for s in doc_view["visible_scope"] if s["subject"] == "user:bob"][0]
        self.assertEqual(bob["status"], "active")
        self.assertEqual(
            svc2.get_change_request(rid)["steps"][0]["status"], "pending")
        self.assertEqual(len(svc2.list_events()["events"]), len(events_before))

        # 继续推进时钟至授权过期
        self.advance(501)
        svc3 = DocumentFlowService(self.tmp, clock=lambda: self.clock_now)
        with self.assertRaises(ServiceError) as cm:
            svc3.download(doc_id, "bob")
        self.assertEqual(cm.exception.code, "AUTH_EXPIRED")

    def test_audit_reconciled_after_restart(self):
        doc_id = self.svc.create_document("简报", b"body", "alice")["document"]["document_id"]
        self.svc.grant(doc_id, "user:bob", "alice")
        state_events = self.svc.list_events()["events"]
        svc2 = DocumentFlowService(self.tmp, clock=lambda: self.clock_now)
        audit = svc2.read_audit_log()["events"]
        self.assertEqual([e["seq"] for e in audit],
                         [e["seq"] for e in state_events])


class TestHTTP(FlowTestBase):
    def setUp(self):
        super().setUp()
        handler = make_handler(self.svc)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def call(self, method, path, payload=None):
        data = None if payload is None else json.dumps(payload).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_full_flow_over_http(self):
        status, body = self.call("POST", "/documents", {
            "title": "行动简报", "content": "机密正文XYZ", "created_by": "alice",
            "initial_level": "内部"})
        self.assertEqual(status, 201)
        doc_id = body["data"]["document"]["document_id"]
        self.assertEqual(body["data"]["document"]["current_level"]["name"], "内部")

        # 错误响应明确携带当前密级/待审批节点/可见范围
        status, body = self.call("POST", f"/documents/{doc_id}/change-requests", {
            "target_level": "机密", "reason": "升级", "requested_by": "alice"})
        self.assertEqual(status, 201)
        rid = body["data"]["request_id"]

        # 错误审批人
        status, body = self.call("POST", f"/change-requests/{rid}/approve",
                                 {"approver": "sec-topsecret"})
        self.assertEqual(status, 403)

        status, body = self.call("POST", f"/change-requests/{rid}/approve",
                                 {"approver": "sec-secret"})
        self.assertEqual(status, 200)
        status, body = self.call("POST", f"/change-requests/{rid}/approve",
                                 {"approver": "sec-topsecret"})
        self.assertEqual(status, 200)

        # 未授权下载 → 403 且响应含当前密级与可见范围
        status, body = self.call("POST", f"/documents/{doc_id}/download",
                                 {"user": "bob", "dept": "ops"})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "NOT_IN_SCOPE")
        self.assertEqual(body["error"]["current_level"]["name"], "机密")
        self.assertIn("visible_scope", body["error"])

        # 授权后下载，得到水印与 base64 正文
        self.call("POST", f"/documents/{doc_id}/grants",
                  {"subject": "dept:ops", "granted_by": "alice"})
        status, body = self.call("POST", f"/documents/{doc_id}/download",
                                 {"user": "bob", "dept": "ops"})
        self.assertEqual(status, 200)
        self.assertEqual(base64.b64decode(body["data"]["content_base64"]).decode(),
                         "机密正文XYZ")
        self.assertIn("watermark", body["data"])

        # 导出清单不得含正文
        status, body = self.call("GET", "/export")
        self.assertNotIn("机密正文XYZ", json.dumps(body, ensure_ascii=False))

        # 驳回理由
        self.call("POST", f"/documents/{doc_id}/change-requests", {
            "target_level": "内部", "reason": "降密", "requested_by": "alice"})
        rid2 = self.svc.list_change_requests(doc_id)["change_requests"][-1]["request_id"]
        status, body = self.call("POST", f"/change-requests/{rid2}/reject",
                                 {"approver": "sec-topsecret", "reason": "仍在任务期"})
        self.assertEqual(status, 200)
        docv = self.call("GET", f"/documents/{doc_id}")[1]["data"]
        self.assertEqual(docv["rejection_reason"]["reason"], "仍在任务期")

        # 审计接口包含全部事件类型
        status, body = self.call("GET", "/audit")
        types = {e["type"] for e in body["data"]["events"]}
        self.assertIn("access_denied", types)
        self.assertIn("download", types)
        self.assertIn("change_rejected", types)


if __name__ == "__main__":
    unittest.main(verbosity=2)
