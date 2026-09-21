"""HTTP 接口层冒烟测试：真实起服务、走 JSON 路由。"""
import base64
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api import make_server  # noqa: E402


class ApiSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        db = os.path.join(cls.tmp.name, "api.db")
        cls.server = make_server(db, "127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def call(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        payload = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if payload else {}
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        data = json.loads(resp.read().decode())
        conn.close()
        return resp.status, data

    def test_end_to_end_flow(self):
        # 注册用户
        status, r = self.call("POST", "/users", {
            "user_id": "admin", "name": "保密管理员", "department": "保密办",
            "clearance": "TOP_SECRET", "roles": ["security_admin"]})
        self.assertEqual(status, 200, r)
        status, r = self.call("POST", "/users", {
            "user_id": "alice", "name": "爱丽丝", "department": "一部",
            "clearance": "SECRET", "roles": ["staff"]})
        self.assertEqual(status, 200, r)

        # 建文档（正文 base64 传输）
        content_b64 = base64.b64encode("机密简报正文".encode()).decode()
        status, r = self.call("POST", "/documents", {
            "actor": "admin", "title": "行动简报", "owner_department": "一部",
            "classification": "SECRET", "content_b64": content_b64})
        self.assertEqual(status, 200, r)
        doc_id = r["doc_id"]
        self.assertEqual(r["document"]["current_classification"]["level"],
                         "SECRET")

        # 未授权下载 -> 403，响应含拒绝理由与可见范围
        status, r = self.call("POST", f"/documents/{doc_id}/download",
                              {"actor": "alice"})
        self.assertEqual(status, 403, r)
        self.assertEqual(r["code"], "NOT_IN_SCOPE")
        self.assertTrue(r["reason"])
        self.assertIn("visible_scope", r["document"])

        # 授权后下载 -> 含水印
        status, r = self.call("POST", f"/documents/{doc_id}/grants", {
            "actor": "admin", "subject_type": "user", "subject_id": "alice"})
        self.assertEqual(status, 200, r)
        status, r = self.call("POST", f"/documents/{doc_id}/download",
                              {"actor": "alice"})
        self.assertEqual(status, 200, r)
        self.assertTrue(r["watermark"]["id"].startswith("WM-"))
        self.assertEqual(
            base64.b64decode(r["content_b64"]).decode(), "机密简报正文")

        # 提出逐级变更 -> 队列可见 -> 清单不含正文
        status, r = self.call(
            "POST", f"/documents/{doc_id}/classification-changes",
            {"actor": "admin", "target_level": "CONFIDENTIAL",
             "reason": "提级"})
        self.assertEqual(status, 200, r)
        self.assertEqual(r["request"]["current_node"]["role"],
                         "dept_security_officer")
        status, r = self.call("GET", "/approval-queue")
        self.assertEqual(status, 200)
        self.assertEqual(r["pending_count"], 1)
        status, r = self.call("GET", "/manifest?actor=admin")
        self.assertEqual(status, 200)
        self.assertNotIn("机密简报正文", json.dumps(r, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
