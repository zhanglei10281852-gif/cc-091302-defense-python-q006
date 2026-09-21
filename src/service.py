"""敏感文档分级流转服务。

能力概览
--------
* 文档与版本管理：重复内容按 SHA-256 识别为已有版本（去重）。
* 密级变更：只能沿审批链逐级升降；每个节点由对应密级的审批人处理，
  支持逐级审批、驳回（带理由）与撤销申请；审批未完成期间文档保持原密级、
  原权限提供服务。
* 阅知范围：按用户/部门授权，支持有效期；撤销即时生效，新请求立即拒绝。
* 下载水印：每次成功下载签发带身份与时间戳的水印并留痕，拒绝访问同样留痕。
* 审计：审计日志为只增 JSONL，任何撤销/驳回都不抹除历史。
* 持久化：状态文件以“临时文件 + fsync + 原子替换”写入，重启后审批队列、
  授权有效期、访问事件完全一致；若审计行在崩溃中丢失则由状态事件补写。

无第三方依赖，仅使用 Python 3.11 标准库；可作为库使用，也可直接启动 HTTP 服务。
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
import re
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# 密级与审批链
# ---------------------------------------------------------------------------

# 密级按 rank 从小到大；审批人即每个密级的定密责任人。
# 升级：进入某密级由该密级审批人批准；降级：离开某密级由该密级审批人释放。
DEFAULT_LEVELS: tuple[dict[str, Any], ...] = (
    {"rank": 1, "name": "公开", "approver": "sec-public"},
    {"rank": 2, "name": "内部", "approver": "sec-internal"},
    {"rank": 3, "name": "秘密", "approver": "sec-secret"},
    {"rank": 4, "name": "机密", "approver": "sec-topsecret"},
)

DEFAULT_INITIAL_RANK = 2  # 新文档默认“内部”


class ServiceError(Exception):
    """业务错误，携带 HTTP 状态码、机器可读代码与面向用户的拒绝理由。"""

    def __init__(self, message: str, *, status: int = 400, code: str = "BAD_REQUEST"):
        super().__init__(message)
        self.status = status
        self.code = code

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": str(self)}


def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _parse_time(value: Any, field: str = "expires_at") -> Optional[float]:
    """接受 epoch 秒（数字）或 ISO-8601 字符串。"""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(text).timestamp()
        except ValueError as exc:
            raise ServiceError(f"{field} 时间格式无法识别: {value}", code="INVALID_TIME") from exc
    raise ServiceError(f"{field} 必须是时间戳或 ISO-8601 字符串", code="INVALID_TIME")


# ---------------------------------------------------------------------------
# 存储：状态快照 + 只增审计日志 + 内容寻址正文
# ---------------------------------------------------------------------------

class _Storage:
    """文件存储。状态文件原子写；审计日志只增；正文按内容哈希存 blob。"""

    STATE_NAME = "state.json"
    AUDIT_NAME = "audit.jsonl"
    LOCK_NAME = ".lock"
    BLOB_DIR = "blobs"

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        os.makedirs(os.path.join(data_dir, self.BLOB_DIR), exist_ok=True)
        self._lock = threading.RLock()
        self._fh_lock: Optional[Any] = None
        try:
            import fcntl  # 仅 POSIX 可用
        except ImportError:
            self._fcntl = None
            self._fh_lock = None
        else:
            self._fcntl = fcntl
            self._fh_lock = open(os.path.join(data_dir, self.LOCK_NAME), "a+")

    def __enter__(self) -> "_Storage":
        self._lock.acquire()
        if self._fh_lock is not None and self._fcntl is not None:
            self._fcntl.flock(self._fh_lock.fileno(), self._fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._fh_lock is not None and self._fcntl is not None:
            self._fcntl.flock(self._fh_lock.fileno(), self._fcntl.LOCK_UN)
        self._lock.release()

    def close(self) -> None:
        if self._fh_lock is not None:
            self._fh_lock.close()
            self._fh_lock = None

    # -- 状态 --------------------------------------------------------------
    def load_state(self) -> dict[str, Any]:
        path = os.path.join(self.data_dir, self.STATE_NAME)
        if not os.path.exists(path):
            return self._empty_state()
        with open(path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        self._reconcile_audit(state)
        return state

    @staticmethod
    def _empty_state() -> dict[str, Any]:
        return {
            "documents": {},
            "change_requests": {},
            "events": [],
            "last_event_seq": 0,
        }

    def save_state(self, state: dict[str, Any]) -> None:
        """原子替换状态文件：临时文件 fsync 后 rename，再 fsync 目录。"""
        path = os.path.join(self.data_dir, self.STATE_NAME)
        fd, tmp = tempfile.mkstemp(prefix=".state.", suffix=".tmp", dir=self.data_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state, fh, ensure_ascii=False, separators=(",", ":"))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
            dir_fd = os.open(self.data_dir, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    # -- 审计 --------------------------------------------------------------
    def append_audit(self, event: dict[str, Any]) -> None:
        path = os.path.join(self.data_dir, self.AUDIT_NAME)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def read_audit(self) -> list[dict[str, Any]]:
        path = os.path.join(self.data_dir, self.AUDIT_NAME)
        if not os.path.exists(path):
            return []
        events: list[dict[str, Any]] = []
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events

    def _reconcile_audit(self, state: dict[str, Any]) -> None:
        """崩溃恢复：状态已提交但审计行缺失时，由状态事件补写（标记 recovered）。

        状态文件是事实源且原子提交，因此不会出现“审计声称授权生效、状态却没有”
        的偏差；只可能缺少最末尾一两条审计行，此处补齐以保证审计完整。
        """
        audit = self.read_audit()
        have_seqs = {e.get("seq") for e in audit}
        missing = [e for e in state.get("events", []) if e.get("seq") not in have_seqs]
        for event in missing:
            recovered = dict(event)
            recovered["recovered"] = True
            self.append_audit(recovered)

    # -- 正文 blob ----------------------------------------------------------
    def put_blob(self, content: bytes) -> str:
        digest = hashlib.sha256(content).hexdigest()
        path = os.path.join(self.data_dir, self.BLOB_DIR, digest)
        if not os.path.exists(path):
            fd, tmp = tempfile.mkstemp(prefix=".blob.", dir=self.data_dir)
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(content)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, path)
            except BaseException:
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise
        return digest

    def get_blob(self, digest: str) -> bytes:
        path = os.path.join(self.data_dir, self.BLOB_DIR, digest)
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not os.path.exists(path):
            raise ServiceError("版本正文不存在", status=404, code="BLOB_NOT_FOUND")
        with open(path, "rb") as fh:
            return fh.read()


# ---------------------------------------------------------------------------
# 领域服务
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class _Scope:
    subject: str
    granted_by: str
    granted_at: float
    expires_at: Optional[float]
    active: bool = True
    revoked_by: Optional[str] = None
    revoked_at: Optional[float] = None

    def effective(self, now: float) -> bool:
        return self.active and (self.expires_at is None or self.expires_at > now)

    def status(self, now: float) -> str:
        if not self.active:
            return "revoked"
        if self.expires_at is not None and self.expires_at <= now:
            return "expired"
        return "active"

    def to_dict(self, now: float) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "granted_by": self.granted_by,
            "granted_at": self.granted_at,
            "granted_at_iso": _iso(self.granted_at),
            "expires_at": self.expires_at,
            "expires_at_iso": _iso(self.expires_at),
            "status": self.status(now),
            "effective": self.effective(now),
            "revoked_by": self.revoked_by,
            "revoked_at": self.revoked_at,
        }


class DocumentFlowService:
    """文档分级流转领域服务（线程安全，可直接实例化使用）。"""

    def __init__(
        self,
        data_dir: str = "./data",
        *,
        levels: tuple[dict[str, Any], ...] = DEFAULT_LEVELS,
        clock: Callable[[], float] = time.time,
    ):
        self.storage = _Storage(data_dir)
        self.state = self.storage.load_state()
        self.levels = sorted(levels, key=lambda item: item["rank"])
        self._by_rank = {item["rank"]: item for item in self.levels}
        self._by_name = {item["name"]: item for item in self.levels}
        self.clock = clock
        self.ready = True

    def close(self) -> None:
        self.storage.close()

    # -- 内部工具 -----------------------------------------------------------

    def _new_id(self, prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex[:12]}"

    def _resolve_rank(self, level: Any) -> int:
        if isinstance(level, int) and level in self._by_rank:
            return level
        if isinstance(level, str):
            if level in self._by_name:
                return self._by_name[level]["rank"]
            if level.isdigit() and int(level) in self._by_rank:
                return int(level)
        raise ServiceError(f"未知密级: {level}", status=404, code="UNKNOWN_LEVEL")

    def _level_view(self, rank: int) -> dict[str, Any]:
        item = self._by_rank[rank]
        return {"rank": rank, "name": item["name"], "approver": item["approver"]}

    def _get_doc(self, doc_id: str) -> dict[str, Any]:
        doc = self.state["documents"].get(doc_id)
        if doc is None:
            raise ServiceError(f"文档不存在: {doc_id}", status=404, code="DOCUMENT_NOT_FOUND")
        return doc

    def _get_request(self, request_id: str) -> dict[str, Any]:
        req = self.state["change_requests"].get(request_id)
        if req is None:
            raise ServiceError(f"变更申请不存在: {request_id}", status=404, code="REQUEST_NOT_FOUND")
        return req

    def _open_request(self, doc: dict[str, Any]) -> Optional[dict[str, Any]]:
        for req in self.state["change_requests"].values():
            if req["document_id"] == doc["id"] and req["status"] == "pending":
                return req
        return None

    def _pending_node(self, doc: dict[str, Any]) -> Optional[dict[str, Any]]:
        req = self._open_request(doc)
        if req is None:
            return None
        step = next(s for s in req["steps"] if s["status"] == "pending")
        node_rank = step["node_rank"]
        return {
            "request_id": req["id"],
            "step_index": step["index"],
            "total_steps": len(req["steps"]),
            "direction": "upgrade" if req["target_rank"] > req["from_rank"] else "downgrade",
            "level": self._level_view(node_rank),
            "approver": self._by_rank[node_rank]["approver"],
            "reason": req["reason"],
        }

    def _last_rejection(self, doc: dict[str, Any]) -> Optional[dict[str, Any]]:
        latest = None
        for req in self.state["change_requests"].values():
            if req["document_id"] == doc["id"] and req["status"] == "rejected":
                if latest is None or req["decided_at"] > latest["decided_at"]:
                    latest = req
        if latest is None:
            return None
        return {
            "request_id": latest["id"],
            "reason": latest["rejection_reason"],
            "rejected_by": latest["rejected_by"],
            "rejected_at": latest["decided_at"],
            "rejected_at_iso": _iso(latest["decided_at"]),
        }

    def _scopes(self, doc: dict[str, Any]) -> list[_Scope]:
        now = self.clock()
        return [_Scope(**kw) for kw in doc["grants"].values()]  # type: ignore[arg-type]

    def _scope_view(self, doc: dict[str, Any]) -> list[dict[str, Any]]:
        now = self.clock()
        return [scope.to_dict(now) for scope in sorted(self._scopes(doc), key=lambda s: s.granted_at)]

    def _record(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """生成事件：先入状态（随状态原子提交），再追加只增审计日志。"""
        seq = self.state["last_event_seq"] + 1
        event = {"seq": seq, "type": event_type, "at": self.clock(), **payload}
        self.state["events"].append(event)
        self.state["last_event_seq"] = seq
        self.storage.save_state(self.state)
        self.storage.append_audit(event)
        return event

    def _doc_view(self, doc: dict[str, Any], *, include_versions: bool = True) -> dict[str, Any]:
        view: dict[str, Any] = {
            "document_id": doc["id"],
            "title": doc["title"],
            "owner": doc["owner"],
            "current_level": self._level_view(doc["current_rank"]),
            "pending_node": self._pending_node(doc),
            "rejection_reason": self._last_rejection(doc),
            "visible_scope": self._scope_view(doc),
            "latest_version": doc["versions"][-1]["version"] if doc["versions"] else None,
        }
        if include_versions:
            view["versions"] = [
                {
                    "version": v["version"],
                    "content_hash": v["content_hash"],
                    "size": v["size"],
                    "created_by": v["created_by"],
                    "created_at": v["created_at"],
                    "created_at_iso": _iso(v["created_at"]),
                    # 注意：任何清单/视图都不包含正文字段
                }
                for v in doc["versions"]
            ]
        return view

    # -- 文档与版本 ---------------------------------------------------------

    def create_document(
        self,
        title: str,
        content: bytes,
        created_by: str,
        *,
        initial_level: Any = None,
    ) -> dict[str, Any]:
        if not title or not str(title).strip():
            raise ServiceError("文档标题不能为空", code="INVALID_TITLE")
        if not isinstance(content, (bytes, bytearray)) or len(content) == 0:
            raise ServiceError("文档正文不能为空", code="INVALID_CONTENT")
        if not created_by:
            raise ServiceError("缺少创建人", code="INVALID_ACTOR")
        rank = DEFAULT_INITIAL_RANK if initial_level is None else self._resolve_rank(initial_level)
        with self.storage:
            now = self.clock()
            digest = self.storage.put_blob(bytes(content))
            doc_id = self._new_id("doc")
            doc = {
                "id": doc_id,
                "title": title,
                "owner": created_by,
                "current_rank": rank,
                "created_at": now,
                "versions": [
                    {
                        "version": 1,
                        "content_hash": digest,
                        "size": len(content),
                        "created_by": created_by,
                        "created_at": now,
                    }
                ],
                "grants": {
                    f"user:{created_by}": {
                        "subject": f"user:{created_by}",
                        "granted_by": created_by,
                        "granted_at": now,
                        "expires_at": None,
                    }
                },
            }
            self.state["documents"][doc_id] = doc
            self._record(
                "document_created",
                {"document_id": doc_id, "title": title, "by": created_by, "level_rank": rank,
                 "content_hash": digest},
            )
            return {"dedup": False, "document": self._doc_view(doc)}

    def add_version(self, doc_id: str, content: bytes, created_by: str) -> dict[str, Any]:
        if not isinstance(content, (bytes, bytearray)) or len(content) == 0:
            raise ServiceError("版本正文不能为空", code="INVALID_CONTENT")
        with self.storage:
            doc = self._get_doc(doc_id)
            digest = self.storage.put_blob(bytes(content))
            for existing in doc["versions"]:
                if existing["content_hash"] == digest:
                    # 重复上传同一内容：识别为已有版本，不生成新版本号
                    self._record(
                        "version_dedup",
                        {"document_id": doc_id, "version": existing["version"],
                         "content_hash": digest, "by": created_by},
                    )
                    return {"dedup": True, "version": existing["version"],
                            "content_hash": digest, "document": self._doc_view(doc)}
            version = doc["versions"][-1]["version"] + 1
            doc["versions"].append({
                "version": version,
                "content_hash": digest,
                "size": len(content),
                "created_by": created_by,
                "created_at": self.clock(),
            })
            self._record(
                "version_created",
                {"document_id": doc_id, "version": version, "content_hash": digest,
                 "by": created_by},
            )
            return {"dedup": False, "version": version, "content_hash": digest,
                    "document": self._doc_view(doc)}

    def get_document(self, doc_id: str) -> dict[str, Any]:
        with self.storage:
            return self._doc_view(self._get_doc(doc_id))

    def export_manifest(self) -> dict[str, Any]:
        """导出全量清单：仅元数据（密级、版本指纹、可见范围），绝不含正文。"""
        with self.storage:
            return {
                "exported_at": self.clock(),
                "exported_at_iso": _iso(self.clock()),
                "documents": [self._doc_view(doc) for doc in self.state["documents"].values()],
            }

    # -- 密级变更 -----------------------------------------------------------

    def request_change(
        self, doc_id: str, target_level: Any, reason: str, requested_by: str
    ) -> dict[str, Any]:
        if not reason or not str(reason).strip():
            raise ServiceError("变更申请必须说明理由", code="INVALID_REASON")
        target_rank = self._resolve_rank(target_level)
        with self.storage:
            doc = self._get_doc(doc_id)
            if self._open_request(doc) is not None:
                raise ServiceError("该文档已有待审批的密级变更，请先结案",
                                   status=409, code="REQUEST_ALREADY_OPEN")
            from_rank = doc["current_rank"]
            if target_rank == from_rank:
                raise ServiceError("目标密级与当前密级相同，无需变更",
                                   code="SAME_LEVEL")
            upward = target_rank > from_rank
            steps = []
            if upward:
                # 升级：逐级进入，由进入方密级的审批人批准
                for index, node_rank in enumerate(
                    range(from_rank + 1, target_rank + 1), start=1
                ):
                    steps.append({
                        "index": index,
                        "from_rank": node_rank - 1,
                        "to_rank": node_rank,
                        "node_rank": node_rank,
                        "approver": self._by_rank[node_rank]["approver"],
                        "status": "pending",
                        "decided_by": None,
                        "decided_at": None,
                    })
            else:
                # 降级：逐级离开，由离开方密级的审批人释放
                for index, node_rank in enumerate(
                    range(from_rank, target_rank, -1), start=1
                ):
                    steps.append({
                        "index": index,
                        "from_rank": node_rank,
                        "to_rank": node_rank - 1,
                        "node_rank": node_rank,
                        "approver": self._by_rank[node_rank]["approver"],
                        "status": "pending",
                        "decided_by": None,
                        "decided_at": None,
                    })
            req_id = self._new_id("cr")
            req = {
                "id": req_id,
                "document_id": doc_id,
                "from_rank": from_rank,
                "target_rank": target_rank,
                "reason": reason,
                "requested_by": requested_by,
                "created_at": self.clock(),
                "status": "pending",
                "steps": steps,
                "rejection_reason": None,
                "rejected_by": None,
                "decided_at": None,
            }
            self.state["change_requests"][req_id] = req
            self._record(
                "change_requested",
                {"request_id": req_id, "document_id": doc_id, "from_rank": from_rank,
                 "target_rank": target_rank, "by": requested_by, "reason": reason},
            )
            return self._request_view(req)

    def _current_step(self, req: dict[str, Any]) -> dict[str, Any]:
        pending = [s for s in req["steps"] if s["status"] == "pending"]
        if not pending:
            raise ServiceError("该申请已结案", status=409, code="REQUEST_CLOSED")
        return pending[0]

    def approve_change(self, request_id: str, approver: str) -> dict[str, Any]:
        with self.storage:
            req = self._get_request(request_id)
            doc = self._get_doc(req["document_id"])
            step = self._current_step(req)
            if approver != step["approver"]:
                raise ServiceError(
                    f"审批人不匹配：当前待审批节点为 {self._by_rank[step['node_rank']]['name']}"
                    f"（审批人 {step['approver']}）",
                    status=403, code="WRONG_APPROVER",
                )
            step["status"] = "approved"
            step["decided_by"] = approver
            step["decided_at"] = self.clock()
            self._record(
                "change_step_approved",
                {"request_id": request_id, "document_id": doc["id"],
                 "step_index": step["index"], "node_rank": step["node_rank"],
                 "from_rank": step["from_rank"], "to_rank": step["to_rank"],
                 "by": approver},
            )
            if all(s["status"] == "approved" for s in req["steps"]):
                req["status"] = "approved"
                req["decided_at"] = self.clock()
                old_rank = doc["current_rank"]
                doc["current_rank"] = req["target_rank"]
                self._record(
                    "classification_changed",
                    {"request_id": request_id, "document_id": doc["id"],
                     "old_rank": old_rank, "new_rank": req["target_rank"], "by": approver},
                )
            return self._request_view(req)

    def reject_change(self, request_id: str, approver: str, reason: str) -> dict[str, Any]:
        if not reason or not str(reason).strip():
            raise ServiceError("驳回必须填写拒绝理由", code="INVALID_REASON")
        with self.storage:
            req = self._get_request(request_id)
            doc = self._get_doc(req["document_id"])
            step = self._current_step(req)
            if approver != step["approver"]:
                raise ServiceError(
                    f"审批人不匹配：当前待审批节点为 {self._by_rank[step['node_rank']]['name']}"
                    f"（审批人 {step['approver']}）",
                    status=403, code="WRONG_APPROVER",
                )
            now = self.clock()
            step["status"] = "rejected"
            step["decided_by"] = approver
            step["decided_at"] = now
            req["status"] = "rejected"
            req["rejection_reason"] = reason
            req["rejected_by"] = approver
            req["decided_at"] = now
            # 驳回不改密级：旧版本继续按原权限提供
            self._record(
                "change_rejected",
                {"request_id": request_id, "document_id": doc["id"],
                 "step_index": step["index"], "node_rank": step["node_rank"],
                 "by": approver, "reason": reason},
            )
            return self._request_view(req)

    def cancel_change(self, request_id: str, requested_by: str) -> dict[str, Any]:
        with self.storage:
            req = self._get_request(request_id)
            doc = self._get_doc(req["document_id"])
            if requested_by != req["requested_by"] and requested_by != doc["owner"]:
                raise ServiceError("仅申请人或文档所有者可撤销申请",
                                   status=403, code="FORBIDDEN")
            self._current_step(req)
            req["status"] = "cancelled"
            req["decided_at"] = self.clock()
            self._record(
                "change_cancelled",
                {"request_id": request_id, "document_id": doc["id"], "by": requested_by},
            )
            return self._request_view(req)

    def get_change_request(self, request_id: str) -> dict[str, Any]:
        with self.storage:
            return self._request_view(self._get_request(request_id))

    def list_change_requests(self, doc_id: Optional[str] = None) -> dict[str, Any]:
        with self.storage:
            reqs = list(self.state["change_requests"].values())
            if doc_id is not None:
                self._get_doc(doc_id)
                reqs = [r for r in reqs if r["document_id"] == doc_id]
            return {"change_requests": [self._request_view(r) for r in
                                        sorted(reqs, key=lambda r: r["created_at"])]}

    def _request_view(self, req: dict[str, Any]) -> dict[str, Any]:
        doc = self._get_doc(req["document_id"])
        current_step = next((s for s in req["steps"] if s["status"] == "pending"), None)
        pending_node = None
        if req["status"] == "pending" and current_step is not None:
            node_rank = current_step["node_rank"]
            pending_node = {
                "step_index": current_step["index"],
                "total_steps": len(req["steps"]),
                "level": self._level_view(node_rank),
                "approver": current_step["approver"],
            }
        return {
            "request_id": req["id"],
            "document_id": req["document_id"],
            "requested_by": req["requested_by"],
            "reason": req["reason"],
            "from_level": self._level_view(req["from_rank"]),
            "target_level": self._level_view(req["target_rank"]),
            "status": req["status"],
            "steps": [
                {
                    "index": s["index"],
                    "from_level": self._level_view(s["from_rank"]),
                    "to_level": self._level_view(s["to_rank"]),
                    "node_level": self._level_view(s["node_rank"]),
                    "approver": s["approver"],
                    "status": s["status"],
                    "decided_by": s["decided_by"],
                    "decided_at_iso": _iso(s["decided_at"]),
                }
                for s in req["steps"]
            ],
            "pending_node": pending_node,
            "rejection_reason": req["rejection_reason"],
            "rejected_by": req["rejected_by"],
            "current_level": self._level_view(doc["current_rank"]),
            "visible_scope": self._scope_view(doc),
        }

    # -- 阅知范围 -----------------------------------------------------------

    @staticmethod
    def _normalize_subject(subject: str) -> str:
        if not isinstance(subject, str) or not re.fullmatch(r"(user|dept):[^\s:]+", subject):
            raise ServiceError("授权对象格式应为 user:<账号> 或 dept:<部门>",
                               code="INVALID_SUBJECT")
        return subject

    def grant(
        self,
        doc_id: str,
        subject: str,
        granted_by: str,
        *,
        expires_at: Any = None,
    ) -> dict[str, Any]:
        subject = self._normalize_subject(subject)
        expiry = _parse_time(expires_at)
        if expiry is not None and expiry <= self.clock():
            raise ServiceError("授权有效期不能早于当前时间", code="INVALID_TIME")
        with self.storage:
            doc = self._get_doc(doc_id)
            now = self.clock()
            # 重新授权会覆盖此前已撤销/过期的记录；历史仍保留在审计日志中
            doc["grants"][subject] = {
                "subject": subject,
                "granted_by": granted_by,
                "granted_at": now,
                "expires_at": expiry,
            }
            self._record(
                "access_granted",
                {"document_id": doc_id, "subject": subject, "by": granted_by,
                 "expires_at": expiry},
            )
            return {"document": self._doc_view(doc)}

    def revoke(self, doc_id: str, subject: str, revoked_by: str) -> dict[str, Any]:
        subject = self._normalize_subject(subject)
        with self.storage:
            doc = self._get_doc(doc_id)
            data = doc["grants"].get(subject)
            if data is None:
                raise ServiceError(f"授权不存在: {subject}", status=404, code="GRANT_NOT_FOUND")
            scope = _Scope(**data)  # type: ignore[arg-type]
            if not scope.active:
                raise ServiceError("该授权此前已撤销", status=409, code="ALREADY_REVOKED")
            scope.active = False
            scope.revoked_by = revoked_by
            scope.revoked_at = self.clock()
            doc["grants"][subject] = dataclasses.asdict(scope)
            # 立即生效：不落延迟队列，下一次访问检查即拒绝；审计行只增不删
            self._record(
                "access_revoked",
                {"document_id": doc_id, "subject": subject, "by": revoked_by},
            )
            return {"document": self._doc_view(doc)}

    def _check_scope(
        self, doc: dict[str, Any], user: str, dept: Optional[str]
    ) -> tuple[str, Optional[_Scope]]:
        """返回 (subject, scope)；无权时抛出带明确理由的 403。"""
        now = self.clock()
        candidates = [f"user:{user}"]
        if dept:
            candidates.append(f"dept:{dept}")
        found: Optional[_Scope] = None
        for key in candidates:
            data = doc["grants"].get(key)
            if data is not None:
                scope = _Scope(**data)  # type: ignore[arg-type]
                if scope.status(now) == "revoked":
                    # 撤销记录优先于其它授权？若用户级被撤销但部门级仍有效，
                    # 部门授权仍成立；继续尝试其它候选，仅在全部无效时报撤销。
                    found = found or scope
                    continue
                if scope.effective(now):
                    return key, scope
                found = found or scope
        if found is None:
            raise ServiceError("访问被拒绝：不在文档阅知范围内",
                               status=403, code="NOT_IN_SCOPE")
        status = found.status(now)
        reason = {
            "revoked": "访问被拒绝：授权已被撤销",
            "expired": "访问被拒绝：授权已过期",
        }[status]
        code = {"revoked": "AUTH_REVOKED", "expired": "AUTH_EXPIRED"}[status]
        raise ServiceError(reason, status=403, code=code)

    # -- 下载与水印 ---------------------------------------------------------

    def download(
        self,
        doc_id: str,
        user: str,
        *,
        dept: Optional[str] = None,
        version: Optional[int] = None,
        client_ip: Optional[str] = None,
    ) -> dict[str, Any]:
        if not user:
            raise ServiceError("缺少下载人身份", code="INVALID_ACTOR")
        with self.storage:
            doc = self._get_doc(doc_id)
            try:
                subject, _ = self._check_scope(doc, user, dept)
            except ServiceError as denied:
                # 拒绝访问同样留痕，但不泄露任何正文
                self._record(
                    "access_denied",
                    {"document_id": doc_id, "user": user, "dept": dept,
                     "reason": denied.code, "message": str(denied)},
                )
                raise
            if version is None:
                ver = doc["versions"][-1]
            else:
                match = [v for v in doc["versions"] if v["version"] == version]
                if not match:
                    raise ServiceError(f"版本不存在: v{version}", status=404,
                                       code="VERSION_NOT_FOUND")
                ver = match[0]
            now = self.clock()
            nonce = uuid.uuid4().hex
            watermark_id = f"WM-{doc['id']}-v{ver['version']}-{nonce[:10]}"
            identity = f"{user}@{dept}" if dept else user
            watermark_text = (
                f"【密级:{self._by_rank[doc['current_rank']]['name']}】"
                f"{identity} {_iso(now)} {watermark_id}"
            )
            watermark = {
                "watermark_id": watermark_id,
                "text": watermark_text,
                "document_id": doc_id,
                "version": ver["version"],
                "content_hash": ver["content_hash"],
                "user": user,
                "dept": dept,
                "subject": subject,
                "issued_at": now,
                "issued_at_iso": _iso(now),
                "client_ip": client_ip,
            }
            self._record("download", {"watermark": watermark})
            content = self.storage.get_blob(ver["content_hash"])
            return {
                "content_base64": base64.b64encode(content).decode("ascii"),
                "watermark": watermark,
                "current_level": self._level_view(doc["current_rank"]),
                "pending_node": self._pending_node(doc),
                "visible_scope": self._scope_view(doc),
            }

    # -- 审计 ---------------------------------------------------------------

    def list_events(self, doc_id: Optional[str] = None) -> dict[str, Any]:
        with self.storage:
            events = list(self.state["events"])
            if doc_id is not None:
                self._get_doc(doc_id)
                events = [
                    e for e in events
                    if e.get("document_id") == doc_id
                    or e.get("watermark", {}).get("document_id") == doc_id
                ]
            return {"events": events}

    def read_audit_log(self) -> dict[str, Any]:
        """直接读取只增审计文件（撤销/驳回后的历史同样可查）。"""
        with self.storage:
            return {"events": self.storage.read_audit()}


# ---------------------------------------------------------------------------
# HTTP 接口（标准库 http.server）
# ---------------------------------------------------------------------------

_ROUTES: list[tuple[str, re.Pattern[str], str]] = [
    ("POST", re.compile(r"^/documents$"), "create_document_http"),
    ("GET", re.compile(r"^/documents$"), "list_documents_http"),
    ("GET", re.compile(r"^/export$"), "export_http"),
    ("GET", re.compile(r"^/audit$"), "audit_http"),
    ("GET", re.compile(r"^/health$"), "health_http"),
    ("GET", re.compile(r"^/documents/(?P<doc>[^/]+)$"), "get_document_http"),
    ("POST", re.compile(r"^/documents/(?P<doc>[^/]+)/versions$"), "add_version_http"),
    ("POST", re.compile(r"^/documents/(?P<doc>[^/]+)/change-requests$"), "request_change_http"),
    ("GET", re.compile(r"^/documents/(?P<doc>[^/]+)/change-requests$"), "list_requests_http"),
    ("POST", re.compile(r"^/documents/(?P<doc>[^/]+)/grants$"), "grant_http"),
    ("POST", re.compile(r"^/documents/(?P<doc>[^/]+)/revoke$"), "revoke_http"),
    ("POST", re.compile(r"^/documents/(?P<doc>[^/]+)/download$"), "download_http"),
    ("GET", re.compile(r"^/documents/(?P<doc>[^/]+)/events$"), "events_http"),
    ("GET", re.compile(r"^/change-requests/(?P<rid>[^/]+)$"), "get_request_http"),
    ("POST", re.compile(r"^/change-requests/(?P<rid>[^/]+)/approve$"), "approve_http"),
    ("POST", re.compile(r"^/change-requests/(?P<rid>[^/]+)/reject$"), "reject_http"),
    ("POST", re.compile(r"^/change-requests/(?P<rid>[^/]+)/cancel$"), "cancel_http"),
]


def _decode_content(body: dict[str, Any]) -> bytes:
    if body.get("content_base64") is not None:
        try:
            return base64.b64decode(body["content_base64"], validate=True)
        except Exception as exc:
            raise ServiceError("content_base64 不是合法的 base64", code="INVALID_CONTENT") from exc
    if body.get("content") is not None:
        return str(body["content"]).encode("utf-8")
    raise ServiceError("缺少正文 content 或 content_base64", code="INVALID_CONTENT")


def make_handler(service: DocumentFlowService) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        server_version = "DocFlow/1.0"

        def log_message(self, fmt: str, *args: Any) -> None:  # 静音默认日志
            return

        def _send(self, status: int, payload: Any) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if length == 0:
                return {}
            raw = self.rfile.read(length)
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise ServiceError("请求体不是合法 JSON", code="INVALID_JSON") from exc
            if not isinstance(parsed, dict):
                raise ServiceError("请求体必须是 JSON 对象", code="INVALID_JSON")
            return parsed

        def _error(self, exc: ServiceError) -> None:
            self._send(exc.status, {"ok": False, "error": exc.to_dict()})

        def _doc_error_context(self, doc_id: str) -> dict[str, Any]:
            try:
                view = service.get_document(doc_id)
            except ServiceError:
                return {}
            return {
                "current_level": view["current_level"],
                "pending_node": view["pending_node"],
                "visible_scope": view["visible_scope"],
            }

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

        def _dispatch(self, method: str) -> None:
            path = self.path.split("?", 1)[0]
            for verb, pattern, action in _ROUTES:
                if verb != method:
                    continue
                match = pattern.fullmatch(path)
                if match:
                    try:
                        body = self._body() if method == "POST" else {}
                        getattr(self, action)(body, **match.groupdict())
                    except ServiceError as exc:
                        self._error(exc)
                    except Exception as exc:  # 防御性兜底
                        self._send(500, {"ok": False, "error": {
                            "code": "INTERNAL", "message": f"内部错误: {exc}"}})
                    return
            self._send(404, {"ok": False, "error": {"code": "NOT_FOUND", "message": path}})

        # -- 各端点 ----------------------------------------------------------

        def health_http(self, body: dict[str, Any]) -> None:
            self._send(200, {"ok": True, "data": {"ready": service.ready}})

        def create_document_http(self, body: dict[str, Any]) -> None:
            result = service.create_document(
                title=body.get("title", ""),
                content=_decode_content(body),
                created_by=body.get("created_by") or body.get("user") or "",
                initial_level=body.get("initial_level"),
            )
            self._send(201, {"ok": True, "data": result})

        def add_version_http(self, body: dict[str, Any], doc: str) -> None:
            result = service.add_version(doc, _decode_content(body),
                                         body.get("created_by") or body.get("user") or "")
            self._send(201, {"ok": True, "data": result})

        def get_document_http(self, body: dict[str, Any], doc: str) -> None:
            self._send(200, {"ok": True, "data": service.get_document(doc)})

        def list_documents_http(self, body: dict[str, Any]) -> None:
            self._send(200, {"ok": True, "data": service.export_manifest()})

        def export_http(self, body: dict[str, Any]) -> None:
            self._send(200, {"ok": True, "data": service.export_manifest()})

        def request_change_http(self, body: dict[str, Any], doc: str) -> None:
            try:
                view = service.request_change(
                    doc, body.get("target_level"),
                    body.get("reason", ""), body.get("requested_by") or body.get("user") or "")
            except ServiceError as exc:
                if exc.code in ("REQUEST_ALREADY_OPEN", "SAME_LEVEL", "UNKNOWN_LEVEL"):
                    payload = {"ok": False, "error": {**exc.to_dict(),
                                                      **self._doc_error_context(doc)}}
                    self._send(exc.status, payload)
                    return
                raise
            self._send(201, {"ok": True, "data": view})

        def list_requests_http(self, body: dict[str, Any], doc: str) -> None:
            self._send(200, {"ok": True, "data": service.list_change_requests(doc)})

        def get_request_http(self, body: dict[str, Any], rid: str) -> None:
            self._send(200, {"ok": True, "data": service.get_change_request(rid)})

        def approve_http(self, body: dict[str, Any], rid: str) -> None:
            self._send(200, {"ok": True, "data": service.approve_change(
                rid, body.get("approver") or body.get("user") or "")})

        def reject_http(self, body: dict[str, Any], rid: str) -> None:
            self._send(200, {"ok": True, "data": service.reject_change(
                rid, body.get("approver") or body.get("user") or "", body.get("reason", ""))})

        def cancel_http(self, body: dict[str, Any], rid: str) -> None:
            self._send(200, {"ok": True, "data": service.cancel_change(
                rid, body.get("requested_by") or body.get("user") or "")})

        def grant_http(self, body: dict[str, Any], doc: str) -> None:
            self._send(200, {"ok": True, "data": service.grant(
                doc, body.get("subject", ""), body.get("granted_by") or body.get("user") or "",
                expires_at=body.get("expires_at"))})

        def revoke_http(self, body: dict[str, Any], doc: str) -> None:
            self._send(200, {"ok": True, "data": service.revoke(
                doc, body.get("subject", ""), body.get("revoked_by") or body.get("user") or "")})

        def download_http(self, body: dict[str, Any], doc: str) -> None:
            ip = self.client_address[0] if self.client_address else None
            try:
                result = service.download(
                    doc, body.get("user") or "", dept=body.get("dept"),
                    version=body.get("version"), client_ip=ip)
            except ServiceError as exc:
                if exc.status == 403 or exc.code == "VERSION_NOT_FOUND":
                    ctx = self._doc_error_context(doc)
                    self._send(403 if exc.status == 403 else 404,
                               {"ok": False, "error": {**exc.to_dict(), **ctx}})
                    return
                raise
            self._send(200, {"ok": True, "data": result})

        def events_http(self, body: dict[str, Any], doc: str) -> None:
            self._send(200, {"ok": True, "data": service.list_events(doc)})

        def audit_http(self, body: dict[str, Any]) -> None:
            self._send(200, {"ok": True, "data": service.read_audit_log()})

    return _Handler


def run_server(host: str = "127.0.0.1", port: int = 8080, data_dir: str = "./data") -> None:
    service = DocumentFlowService(data_dir)
    httpd = ThreadingHTTPServer((host, port), make_handler(service))
    print(f"文档分级流转服务监听 http://{host}:{port}（数据目录 {data_dir}）")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


# 兼容既有骨架
class Service(DocumentFlowService):
    """保留给旧入口的薄封装。"""

    def __init__(self, data_dir: str = "./data"):
        super().__init__(data_dir)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="敏感文档分级流转服务")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    parser.add_argument("--data-dir", default=os.environ.get("DATA_DIR", "./data"))
    args = parser.parse_args()
    run_server(args.host, args.port, args.data_dir)
