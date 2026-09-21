"""基于标准库 http.server 的 JSON 接口层。

运行：python -m src.api --db /var/lib/docflow/service.db --port 8080

所有响应为 JSON，业务信封由 DocumentFlowService 返回：
    {"ok", "code", "reason", ...}
HTTP 状态码按 code 映射，正文只出现在下载接口的 content_b64 字段中。
"""
from __future__ import annotations

import argparse
import base64
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .service import DocumentFlowService

# 业务码 -> HTTP 状态码（未列出的失败一律 400）
STATUS_BY_CODE = {
    "UNKNOWN_USER": 403,
    "FORBIDDEN": 403,
    "SELF_APPROVAL": 403,
    "WRONG_APPROVER": 403,
    "CLEARANCE_INSUFFICIENT": 403,
    "NOT_IN_SCOPE": 403,
    "GRANT_EXPIRED": 403,
    "GRANT_REVOKED": 403,
    "DOCUMENT_NOT_FOUND": 404,
    "VERSION_NOT_FOUND": 404,
    "REQUEST_NOT_FOUND": 404,
    "GRANT_NOT_FOUND": 404,
    "SUBJECT_NOT_FOUND": 404,
    "CHANGE_PENDING": 409,
    "ALREADY_REVOKED": 409,
    "NOT_PENDING": 409,
    "SAME_LEVEL": 409,
}


def _b64decode(text):
    try:
        return base64.b64decode(text or "", validate=True)
    except Exception:
        return None


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "DocFlow/1.0"
    service: DocumentFlowService = None  # 由 make_server 注入

    # ---------------- 基础工具 ----------------
    def _send(self, obj):
        code = 200
        if not obj.get("ok", False):
            code = STATUS_BY_CODE.get(obj.get("code"), 400)
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _query(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        return parsed.path, {k: v[0] for k, v in parse_qs(parsed.query).items()}

    def log_message(self, fmt, *args):  # 静默访问日志，审计走 events 表
        pass

    # ---------------- 路由 ----------------
    def do_POST(self):
        path, _ = self._query()
        body = self._body()
        if body is None:
            return self._send({"ok": False, "code": "BAD_JSON",
                               "reason": "请求体不是合法 JSON"})
        svc = self.service
        m = None

        if path == "/users":
            return self._send(svc.register_user(
                body.get("user_id"), body.get("name"), body.get("department"),
                body.get("clearance"), body.get("roles")))
        if path == "/documents":
            content = _b64decode(body.get("content_b64"))
            if content is None:
                return self._send({"ok": False, "code": "BAD_CONTENT",
                                   "reason": "content_b64 不是合法 base64"})
            return self._send(svc.create_document(
                body.get("actor"), body.get("title"), body.get("owner_department"),
                body.get("classification"), content))

        m = re.fullmatch(r"/documents/([^/]+)/versions", path)
        if m:
            content = _b64decode(body.get("content_b64"))
            if content is None:
                return self._send({"ok": False, "code": "BAD_CONTENT",
                                   "reason": "content_b64 不是合法 base64"})
            return self._send(svc.upload_version(body.get("actor"), m.group(1), content))

        m = re.fullmatch(r"/documents/([^/]+)/classification-changes", path)
        if m:
            return self._send(svc.propose_classification_change(
                body.get("actor"), m.group(1), body.get("target_level"),
                body.get("reason", "")))

        m = re.fullmatch(r"/documents/([^/]+)/grants", path)
        if m:
            return self._send(svc.assign_grant(
                body.get("actor"), m.group(1), body.get("subject_type"),
                body.get("subject_id"), body.get("expires_at")))

        m = re.fullmatch(r"/documents/([^/]+)/download", path)
        if m:
            return self._send(svc.download(
                body.get("actor"), m.group(1), body.get("version_seq")))

        m = re.fullmatch(r"/classification-changes/([^/]+)/approve", path)
        if m:
            return self._send(svc.approve_change(
                body.get("actor"), m.group(1), body.get("comment", "")))

        m = re.fullmatch(r"/classification-changes/([^/]+)/reject", path)
        if m:
            return self._send(svc.reject_change(
                body.get("actor"), m.group(1), body.get("reason", "")))

        m = re.fullmatch(r"/classification-changes/([^/]+)/withdraw", path)
        if m:
            return self._send(svc.withdraw_change(body.get("actor"), m.group(1)))

        m = re.fullmatch(r"/grants/([^/]+)/revoke", path)
        if m:
            return self._send(svc.revoke_grant(
                body.get("actor"), m.group(1), body.get("reason", "")))

        return self._send({"ok": False, "code": "NOT_FOUND",
                           "reason": f"未知路由: POST {path}"})

    def do_GET(self):
        path, query = self._query()
        svc = self.service
        m = None

        if path == "/manifest":
            return self._send(svc.export_manifest(query.get("actor")))
        if path == "/approval-queue":
            return self._send(svc.approval_queue(query.get("actor")))

        m = re.fullmatch(r"/documents/([^/]+)", path)
        if m:
            return self._send(svc.get_document_status(query.get("actor"), m.group(1)))

        m = re.fullmatch(r"/documents/([^/]+)/events", path)
        if m:
            return self._send(svc.list_events(query.get("actor"), m.group(1)))

        m = re.fullmatch(r"/documents/([^/]+)/downloads", path)
        if m:
            return self._send(svc.list_downloads(query.get("actor"), m.group(1)))

        return self._send({"ok": False, "code": "NOT_FOUND",
                           "reason": f"未知路由: GET {path}"})


def make_server(db_path, host="127.0.0.1", port=8080):
    service = DocumentFlowService(db_path)

    class Handler(ApiHandler):
        pass

    Handler.service = service
    server = ThreadingHTTPServer((host, port), Handler)
    server.service = service
    return server


def main(argv=None):
    parser = argparse.ArgumentParser(description="敏感文档分级流转服务")
    parser.add_argument("--db", default="docflow.db", help="SQLite 数据文件路径")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    server = make_server(args.db, args.host, args.port)
    print(f"listening on http://{args.host}:{args.port} (db={args.db})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
