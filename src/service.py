"""敏感文档分级流转服务。

职责：
- 文档与版本管理（重复上传按内容哈希识别为已有版本）
- 密级变更申请与逐级审批（审批未完成时旧版本仍按原权限提供）
- 阅知范围分配与撤销（撤销立即生效，历史审计保留）
- 下载水印与访问事件留痕
- 导出清单（只含元数据，不泄露正文）

所有接口返回统一信封：
    {"ok": bool, "code": str, "reason": str|None, ...}
文档相关响应都携带 document 状态块，明确当前密级、待审批节点与可见范围。
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone

from .models import (
    Action,
    DEFAULT_APPROVAL_CHAINS,
    GRANT_MANAGER_ROLES,
    LEVEL_LABELS,
    PRIVILEGED_AUDIT_ROLES,
    Level,
    NodeStatus,
    RequestStatus,
    parse_level,
)
from .storage import Store


def _iso(ts):
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def _new_id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class DocumentFlowService:
    """文档分级流转领域服务。"""

    def __init__(self, db_path: str = ":memory:", approval_chains=None, clock=None):
        self.store = Store(db_path)
        # 审批链可注入，便于按部署环境调整；默认见 models.DEFAULT_APPROVAL_CHAINS
        self.approval_chains = approval_chains or DEFAULT_APPROVAL_CHAINS
        # 时钟可注入，便于测试授权有效期
        self.clock = clock or time.time
        self.ready = True

    # ------------------------------------------------------------------
    # 响应信封
    # ------------------------------------------------------------------
    @staticmethod
    def _ok(code="OK", **payload):
        return {"ok": True, "code": code, "reason": None, **payload}

    @staticmethod
    def _fail(code, reason, **payload):
        return {"ok": False, "code": code, "reason": reason, **payload}

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------
    def _log(self, conn, actor, action, doc_id, detail):
        conn.execute(
            "INSERT INTO events(event_id, ts, actor, action, doc_id, detail)"
            " VALUES (?,?,?,?,?,?)",
            (_new_id("evt"), self.clock(), actor, action, doc_id,
             json.dumps(detail, ensure_ascii=False, sort_keys=True)),
        )

    def _get_user(self, user_id):
        return self.store.one("SELECT * FROM users WHERE user_id=?", (user_id,))

    def _get_doc(self, doc_id):
        return self.store.one("SELECT * FROM documents WHERE doc_id=?", (doc_id,))

    def _user_roles(self, user_row):
        return set(json.loads(user_row["roles"]))

    @staticmethod
    def _level_info(rank):
        level = Level(rank)
        return {"level": level.name, "label": LEVEL_LABELS[level], "rank": int(level)}

    def _parse_time(self, value):
        """接受 epoch 秒或 ISO 8601 字符串。"""
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip()
        try:
            return float(text)
        except ValueError:
            pass
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()

    # ------------------------------------------------------------------
    # 状态块：当前密级 / 待审批节点 / 可见范围
    # ------------------------------------------------------------------
    def _request_detail(self, req):
        nodes = self.store.query(
            "SELECT * FROM approval_nodes WHERE request_id=? ORDER BY seq",
            (req["request_id"],),
        )
        node_list = [
            {
                "seq": n["seq"],
                "role": n["role"],
                "status": n["status"],
                "actor": n["actor"],
                "acted_at": _iso(n["acted_at"]),
                "comment": n["comment"],
            }
            for n in nodes
        ]
        current = next((n for n in node_list if n["status"] == NodeStatus.PENDING), None)
        return {
            "request_id": req["request_id"],
            "doc_id": req["doc_id"],
            "proposer": req["proposer"],
            "from_level": self._level_info(req["from_level"]),
            "to_level": self._level_info(req["to_level"]),
            "direction": req["direction"],
            "reason": req["reason"],
            "status": req["status"],
            "reject_reason": req["reject_reason"],
            "created_at": _iso(req["created_at"]),
            "decided_at": _iso(req["decided_at"]),
            "current_node": current,           # 待审批节点
            "nodes": node_list,
        }

    def _visible_scope(self, doc_id):
        rows = self.store.query(
            "SELECT * FROM grants WHERE doc_id=? ORDER BY granted_at", (doc_id,)
        )
        active, revoked = [], []
        for g in rows:
            item = {
                "grant_id": g["grant_id"],
                "subject_type": g["subject_type"],
                "subject_id": g["subject_id"],
                "granted_by": g["granted_by"],
                "granted_at": _iso(g["granted_at"]),
                "expires_at": _iso(g["expires_at"]),
            }
            if g["revoked_at"] is not None:
                item["revoked_at"] = _iso(g["revoked_at"])
                item["revoke_reason"] = g["revoke_reason"]
                revoked.append(item)
            else:
                active.append(item)
        return {"active_grants": active, "revoked_grants": revoked}

    def _doc_status(self, doc):
        pending = self.store.one(
            "SELECT * FROM change_requests WHERE doc_id=? AND status=?",
            (doc["doc_id"], RequestStatus.PENDING),
        )
        versions = self.store.query(
            "SELECT seq, content_hash, size, uploaded_by, uploaded_at"
            " FROM versions WHERE doc_id=? ORDER BY seq",
            (doc["doc_id"],),
        )
        return {
            "doc_id": doc["doc_id"],
            "title": doc["title"],
            "owner_department": doc["owner_department"],
            "created_by": doc["created_by"],
            "created_at": _iso(doc["created_at"]),
            "current_classification": self._level_info(doc["current_level"]),
            "pending_change": self._request_detail(pending) if pending else None,
            "visible_scope": self._visible_scope(doc["doc_id"]),
            "versions": [
                {
                    "seq": v["seq"],
                    "sha256": v["content_hash"],
                    "size": v["size"],
                    "uploaded_by": v["uploaded_by"],
                    "uploaded_at": _iso(v["uploaded_at"]),
                }
                for v in versions
            ],
        }

    def _status_response(self, doc, **extra):
        return {"document": self._doc_status(doc), **extra}

    # ------------------------------------------------------------------
    # 用户登记（身份供给，无鉴权，由部署环境对接真实目录）
    # ------------------------------------------------------------------
    def register_user(self, user_id, name, department, clearance, roles):
        try:
            level = parse_level(clearance)
        except ValueError as exc:
            return self._fail("INVALID_LEVEL", str(exc))
        if not user_id or not name or not department:
            return self._fail("INVALID_USER", "user_id、name、department 均不能为空")
        roles = list(roles or [])
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO users(user_id, name, department, clearance, roles)"
                " VALUES (?,?,?,?,?)"
                " ON CONFLICT(user_id) DO UPDATE SET"
                " name=excluded.name, department=excluded.department,"
                " clearance=excluded.clearance, roles=excluded.roles",
                (user_id, name, department, int(level), json.dumps(roles)),
            )
            self._log(conn, user_id, Action.USER_REGISTERED, None,
                      {"department": department, "clearance": level.name,
                       "roles": roles})
        return self._ok(user_id=user_id, clearance=self._level_info(level),
                        roles=roles)

    # ------------------------------------------------------------------
    # 文档与版本
    # ------------------------------------------------------------------
    def _content_refs_elsewhere(self, content_hash, exclude_doc_id):
        rows = self.store.query(
            "SELECT DISTINCT doc_id FROM versions WHERE content_hash=? AND doc_id<>?",
            (content_hash, exclude_doc_id),
        )
        return [r["doc_id"] for r in rows]

    def create_document(self, actor, title, owner_department, classification, content):
        user = self._get_user(actor)
        if user is None:
            return self._fail("UNKNOWN_USER", f"用户不存在: {actor}")
        try:
            level = parse_level(classification)
        except ValueError as exc:
            return self._fail("INVALID_LEVEL", str(exc))
        if isinstance(content, str):
            content = content.encode("utf-8")
        if not title:
            return self._fail("INVALID_DOCUMENT", "标题不能为空")

        now = self.clock()
        doc_id = _new_id("doc")
        version_id = _new_id("ver")
        digest = hashlib.sha256(content).hexdigest()
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO documents(doc_id, title, owner_department,"
                " created_by, created_at, current_level) VALUES (?,?,?,?,?,?)",
                (doc_id, title, owner_department, actor, now, int(level)),
            )
            conn.execute(
                "INSERT INTO versions(version_id, doc_id, seq, content_hash,"
                " size, uploaded_by, uploaded_at) VALUES (?,?,?,?,?,?,?)",
                (version_id, doc_id, 1, digest, len(content), actor, now),
            )
            conn.execute(
                "INSERT INTO version_content(version_id, content) VALUES (?,?)",
                (version_id, content),
            )
            self._log(conn, actor, Action.DOC_CREATED, doc_id,
                      {"title": title, "owner_department": owner_department,
                       "classification": level.name})
            self._log(conn, actor, Action.VERSION_UPLOADED, doc_id,
                      {"seq": 1, "sha256": digest, "size": len(content)})
        doc = self._get_doc(doc_id)
        return self._ok("DOCUMENT_CREATED", doc_id=doc_id,
                        also_in_documents=self._content_refs_elsewhere(digest, doc_id),
                        **self._status_response(doc))

    def upload_version(self, actor, doc_id, content):
        user = self._get_user(actor)
        if user is None:
            return self._fail("UNKNOWN_USER", f"用户不存在: {actor}")
        doc = self._get_doc(doc_id)
        if doc is None:
            return self._fail("DOCUMENT_NOT_FOUND", f"文档不存在: {doc_id}")
        if isinstance(content, str):
            content = content.encode("utf-8")
        digest = hashlib.sha256(content).hexdigest()
        now = self.clock()

        existing = self.store.one(
            "SELECT * FROM versions WHERE doc_id=? AND content_hash=?",
            (doc_id, digest),
        )
        if existing is not None:
            # 重复上传同一内容：识别为已有版本，不产生新版本
            with self.store.transaction() as conn:
                self._log(conn, actor, Action.VERSION_DEDUPED, doc_id,
                          {"seq": existing["seq"], "sha256": digest})
            return self._ok(
                "DUPLICATE_CONTENT",
                deduplicated=True,
                version={"seq": existing["seq"], "sha256": digest,
                         "uploaded_by": existing["uploaded_by"],
                         "uploaded_at": _iso(existing["uploaded_at"])},
                also_in_documents=self._content_refs_elsewhere(digest, doc_id),
                **self._status_response(doc),
            )

        row = self.store.one(
            "SELECT COALESCE(MAX(seq), 0) AS m FROM versions WHERE doc_id=?",
            (doc_id,),
        )
        seq = row["m"] + 1
        version_id = _new_id("ver")
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO versions(version_id, doc_id, seq, content_hash,"
                " size, uploaded_by, uploaded_at) VALUES (?,?,?,?,?,?,?)",
                (version_id, doc_id, seq, digest, len(content), actor, now),
            )
            conn.execute(
                "INSERT INTO version_content(version_id, content) VALUES (?,?)",
                (version_id, content),
            )
            self._log(conn, actor, Action.VERSION_UPLOADED, doc_id,
                      {"seq": seq, "sha256": digest, "size": len(content)})
        doc = self._get_doc(doc_id)
        return self._ok(
            "VERSION_CREATED",
            deduplicated=False,
            version={"seq": seq, "sha256": digest},
            also_in_documents=self._content_refs_elsewhere(digest, doc_id),
            **self._status_response(doc),
        )

    # ------------------------------------------------------------------
    # 密级变更：逐级申请、按链审批
    # ------------------------------------------------------------------
    def propose_classification_change(self, actor, doc_id, target_level, reason=""):
        user = self._get_user(actor)
        if user is None:
            return self._fail("UNKNOWN_USER", f"用户不存在: {actor}")
        doc = self._get_doc(doc_id)
        if doc is None:
            return self._fail("DOCUMENT_NOT_FOUND", f"文档不存在: {doc_id}")
        try:
            target = parse_level(target_level)
        except ValueError as exc:
            return self._fail("INVALID_LEVEL", str(exc))

        current = Level(doc["current_level"])
        if target == current:
            return self._fail("SAME_LEVEL", "目标密级与当前密级相同",
                              **self._status_response(doc))
        if abs(int(target) - int(current)) != 1:
            allowed = [Level(int(current) + d)
                       for d in (-1, 1)
                       if 0 <= int(current) + d <= int(Level.TOP_SECRET)]
            return self._fail(
                "NON_STEPWISE",
                "密级只能逐级变更，允许的目标密级: "
                + ", ".join(f"{l.name}({LEVEL_LABELS[l]})" for l in allowed),
                allowed_targets=[self._level_info(l) for l in allowed],
                **self._status_response(doc),
            )

        pending = self.store.one(
            "SELECT * FROM change_requests WHERE doc_id=? AND status=?",
            (doc_id, RequestStatus.PENDING),
        )
        if pending is not None:
            return self._fail(
                "CHANGE_PENDING",
                "存在待审批的密级变更，须先完成或撤回",
                pending_request=self._request_detail(pending),
                **self._status_response(doc),
            )

        direction = "upgrade" if target > current else "downgrade"
        chain = self.approval_chains[direction]
        now = self.clock()
        request_id = _new_id("req")
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO change_requests(request_id, doc_id, proposer,"
                " from_level, to_level, direction, reason, status, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (request_id, doc_id, actor, int(current), int(target),
                 direction, reason, RequestStatus.PENDING, now),
            )
            for seq, role in enumerate(chain, start=1):
                conn.execute(
                    "INSERT INTO approval_nodes(node_id, request_id, seq, role,"
                    " status) VALUES (?,?,?,?,?)",
                    (_new_id("node"), request_id, seq, role, NodeStatus.PENDING),
                )
            self._log(conn, actor, Action.CHANGE_PROPOSED, doc_id,
                      {"request_id": request_id, "from": current.name,
                       "to": target.name, "direction": direction,
                       "chain": list(chain), "reason": reason})
        req = self.store.one(
            "SELECT * FROM change_requests WHERE request_id=?", (request_id,))
        return self._ok("CHANGE_PROPOSED",
                        request=self._request_detail(req),
                        **self._status_response(self._get_doc(doc_id)))

    def _get_pending_request(self, request_id):
        req = self.store.one(
            "SELECT * FROM change_requests WHERE request_id=?", (request_id,))
        if req is None:
            return None, self._fail("REQUEST_NOT_FOUND",
                                    f"变更申请不存在: {request_id}")
        if req["status"] != RequestStatus.PENDING:
            return None, self._fail(
                "NOT_PENDING",
                f"申请已终结（状态 {req['status']}），不能再审批",
                request=self._request_detail(req))
        return req, None

    def _current_node(self, request_id):
        return self.store.one(
            "SELECT * FROM approval_nodes WHERE request_id=? AND status=?"
            " ORDER BY seq LIMIT 1",
            (request_id, NodeStatus.PENDING),
        )

    def approve_change(self, actor, request_id, comment=""):
        user = self._get_user(actor)
        if user is None:
            return self._fail("UNKNOWN_USER", f"用户不存在: {actor}")
        req, err = self._get_pending_request(request_id)
        if err is not None:
            return err
        node = self._current_node(request_id)
        if node is None:
            return self._fail("NOT_PENDING", "申请没有待处理节点",
                              request=self._request_detail(req))
        roles = self._user_roles(user)
        if node["role"] not in roles:
            return self._fail(
                "WRONG_APPROVER",
                f"当前待审批节点为第 {node['seq']} 级，要求角色 {node['role']}",
                required_role=node["role"],
                request=self._request_detail(req),
                **self._status_response(self._get_doc(req["doc_id"])),
            )
        if actor == req["proposer"]:
            return self._fail("SELF_APPROVAL", "申请人不能审批自己提出的变更",
                              request=self._request_detail(req))

        now = self.clock()
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE approval_nodes SET status=?, actor=?, acted_at=?,"
                " comment=? WHERE node_id=?",
                (NodeStatus.APPROVED, actor, now, comment, node["node_id"]),
            )
            self._log(conn, actor, Action.CHANGE_APPROVED, req["doc_id"],
                      {"request_id": request_id, "node_seq": node["seq"],
                       "role": node["role"], "comment": comment})
            remaining = conn.execute(
                "SELECT COUNT(*) AS c FROM approval_nodes WHERE request_id=?"
                " AND status=?",
                (request_id, NodeStatus.PENDING),
            ).fetchone()["c"]
            if remaining == 0:
                # 终审通过：密级在同一事务内生效，此前下载仍按原密级
                conn.execute(
                    "UPDATE change_requests SET status=?, decided_at=?"
                    " WHERE request_id=?",
                    (RequestStatus.EFFECTIVE, now, request_id),
                )
                conn.execute(
                    "UPDATE documents SET current_level=? WHERE doc_id=?",
                    (req["to_level"], req["doc_id"]),
                )
                self._log(conn, actor, Action.CHANGE_EFFECTIVE, req["doc_id"],
                          {"request_id": request_id,
                           "from": Level(req["from_level"]).name,
                           "to": Level(req["to_level"]).name})
        req = self.store.one(
            "SELECT * FROM change_requests WHERE request_id=?", (request_id,))
        return self._ok("CHANGE_APPROVED",
                        request=self._request_detail(req),
                        **self._status_response(self._get_doc(req["doc_id"])))

    def reject_change(self, actor, request_id, reason):
        user = self._get_user(actor)
        if user is None:
            return self._fail("UNKNOWN_USER", f"用户不存在: {actor}")
        if not reason:
            return self._fail("INVALID_REASON", "驳回必须填写理由")
        req, err = self._get_pending_request(request_id)
        if err is not None:
            return err
        node = self._current_node(request_id)
        roles = self._user_roles(user)
        if node is None or node["role"] not in roles:
            need = node["role"] if node else None
            return self._fail(
                "WRONG_APPROVER",
                f"当前待审批节点要求角色 {need}" if need else "申请没有待处理节点",
                request=self._request_detail(req),
            )

        now = self.clock()
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE approval_nodes SET status=?, actor=?, acted_at=?,"
                " comment=? WHERE node_id=?",
                (NodeStatus.REJECTED, actor, now, reason, node["node_id"]),
            )
            conn.execute(
                "UPDATE approval_nodes SET status=? WHERE request_id=?"
                " AND status=?",
                (NodeStatus.SKIPPED, request_id, NodeStatus.PENDING),
            )
            conn.execute(
                "UPDATE change_requests SET status=?, decided_at=?,"
                " reject_reason=? WHERE request_id=?",
                (RequestStatus.REJECTED, now, reason, request_id),
            )
            self._log(conn, actor, Action.CHANGE_REJECTED, req["doc_id"],
                      {"request_id": request_id, "node_seq": node["seq"],
                       "reason": reason})
        req = self.store.one(
            "SELECT * FROM change_requests WHERE request_id=?", (request_id,))
        return self._ok("CHANGE_REJECTED",
                        request=self._request_detail(req),
                        **self._status_response(self._get_doc(req["doc_id"])))

    def withdraw_change(self, actor, request_id):
        req, err = self._get_pending_request(request_id)
        if err is not None:
            return err
        if actor != req["proposer"]:
            return self._fail("FORBIDDEN", "只有申请人可以撤回变更申请",
                              request=self._request_detail(req))
        now = self.clock()
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE change_requests SET status=?, decided_at=?"
                " WHERE request_id=?",
                (RequestStatus.WITHDRAWN, now, request_id),
            )
            conn.execute(
                "UPDATE approval_nodes SET status=? WHERE request_id=?"
                " AND status=?",
                (NodeStatus.SKIPPED, request_id, NodeStatus.PENDING),
            )
            self._log(conn, actor, Action.CHANGE_WITHDRAWN, req["doc_id"],
                      {"request_id": request_id})
        req = self.store.one(
            "SELECT * FROM change_requests WHERE request_id=?", (request_id,))
        return self._ok("CHANGE_WITHDRAWN",
                        request=self._request_detail(req),
                        **self._status_response(self._get_doc(req["doc_id"])))

    # ------------------------------------------------------------------
    # 阅知范围（授权）
    # ------------------------------------------------------------------
    def assign_grant(self, actor, doc_id, subject_type, subject_id, expires_at=None):
        user = self._get_user(actor)
        if user is None:
            return self._fail("UNKNOWN_USER", f"用户不存在: {actor}")
        if not GRANT_MANAGER_ROLES & self._user_roles(user):
            return self._fail("FORBIDDEN", "只有保密管理员或部门保密员可以分配阅知范围")
        doc = self._get_doc(doc_id)
        if doc is None:
            return self._fail("DOCUMENT_NOT_FOUND", f"文档不存在: {doc_id}")
        if subject_type not in ("user", "department"):
            return self._fail("INVALID_SUBJECT", "subject_type 必须是 user 或 department")
        if subject_type == "user" and self._get_user(subject_id) is None:
            return self._fail("SUBJECT_NOT_FOUND", f"授权对象用户不存在: {subject_id}")
        try:
            expires = self._parse_time(expires_at)
        except (ValueError, TypeError):
            return self._fail("INVALID_EXPIRY", f"无法解析有效期: {expires_at!r}")
        now = self.clock()
        if expires is not None and expires <= now:
            return self._fail("INVALID_EXPIRY", "授权有效期必须晚于当前时间")

        existing = self.store.one(
            "SELECT * FROM grants WHERE doc_id=? AND subject_type=?"
            " AND subject_id=? AND revoked_at IS NULL",
            (doc_id, subject_type, subject_id),
        )
        if existing is not None:
            return self._ok("GRANT_EXISTS", grant_id=existing["grant_id"],
                            note="该对象已持有有效授权",
                            **self._status_response(doc))

        grant_id = _new_id("grt")
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO grants(grant_id, doc_id, subject_type, subject_id,"
                " granted_by, granted_at, expires_at) VALUES (?,?,?,?,?,?,?)",
                (grant_id, doc_id, subject_type, subject_id, actor, now, expires),
            )
            self._log(conn, actor, Action.GRANT_ASSIGNED, doc_id,
                      {"grant_id": grant_id, "subject_type": subject_type,
                       "subject_id": subject_id, "expires_at": _iso(expires)})
        return self._ok("GRANT_ASSIGNED", grant_id=grant_id,
                        **self._status_response(doc))

    def revoke_grant(self, actor, grant_id, reason=""):
        user = self._get_user(actor)
        if user is None:
            return self._fail("UNKNOWN_USER", f"用户不存在: {actor}")
        grant = self.store.one("SELECT * FROM grants WHERE grant_id=?", (grant_id,))
        if grant is None:
            return self._fail("GRANT_NOT_FOUND", f"授权不存在: {grant_id}")
        if grant["revoked_at"] is not None:
            return self._fail("ALREADY_REVOKED", "该授权已被撤销",
                              revoked_at=_iso(grant["revoked_at"]))
        roles = self._user_roles(user)
        if not (GRANT_MANAGER_ROLES & roles) and actor != grant["granted_by"]:
            return self._fail("FORBIDDEN", "只有保密管理员、部门保密员或原授权人可以撤销")
        now = self.clock()
        with self.store.transaction() as conn:
            # 只置撤销位，历史授权与审计事件全部保留
            conn.execute(
                "UPDATE grants SET revoked_at=?, revoked_by=?, revoke_reason=?"
                " WHERE grant_id=?",
                (now, actor, reason, grant_id),
            )
            self._log(conn, actor, Action.GRANT_REVOKED, grant["doc_id"],
                      {"grant_id": grant_id, "subject_type": grant["subject_type"],
                       "subject_id": grant["subject_id"], "reason": reason})
        return self._ok("GRANT_REVOKED", grant_id=grant_id,
                        **self._status_response(self._get_doc(grant["doc_id"])))

    # ------------------------------------------------------------------
    # 访问控制与下载水印
    # ------------------------------------------------------------------
    def _covering_grants(self, doc_id, user):
        return self.store.query(
            "SELECT * FROM grants WHERE doc_id=? AND ("
            " (subject_type='user' AND subject_id=?) OR"
            " (subject_type='department' AND subject_id=?))",
            (doc_id, user["user_id"], user["department"]),
        )

    def _evaluate_access(self, user, doc):
        """返回 (allowed, code, reason)。撤销优先于过期，过期优先于未授权。"""
        level = Level(doc["current_level"])
        if int(user["clearance"]) < int(level):
            return False, "CLEARANCE_INSUFFICIENT", (
                f"用户密级 {Level(user['clearance']).name} 低于文档密级 {level.name}")
        now = self.clock()
        grants = self._covering_grants(doc["doc_id"], user)
        for g in grants:
            if g["revoked_at"] is None and (g["expires_at"] is None
                                            or g["expires_at"] > now):
                return True, "OK", ""
        if any(g["revoked_at"] is not None for g in grants):
            return False, "GRANT_REVOKED", "授权已被撤销，新的访问请求立即拒绝"
        if any(g["expires_at"] is not None and g["expires_at"] <= now
               and g["revoked_at"] is None for g in grants):
            return False, "GRANT_EXPIRED", "授权已过有效期"
        return False, "NOT_IN_SCOPE", "用户不在该文档的阅知范围内"

    def download(self, actor, doc_id, version_seq=None):
        user = self._get_user(actor)
        if user is None:
            return self._fail("UNKNOWN_USER", f"用户不存在: {actor}")
        doc = self._get_doc(doc_id)
        if doc is None:
            return self._fail("DOCUMENT_NOT_FOUND", f"文档不存在: {doc_id}")

        allowed, code, reason = self._evaluate_access(user, doc)
        now = self.clock()
        if not allowed:
            # 拒绝也留痕：谁在何时因何原因被拒
            with self.store.transaction() as conn:
                self._log(conn, actor, Action.DOWNLOAD_DENIED, doc_id,
                          {"code": code, "reason": reason,
                           "clearance": Level(user["clearance"]).name,
                           "doc_level": Level(doc["current_level"]).name})
            return self._fail(code, reason, **self._status_response(doc))

        if version_seq is None:
            version = self.store.one(
                "SELECT * FROM versions WHERE doc_id=? ORDER BY seq DESC LIMIT 1",
                (doc_id,))
        else:
            version = self.store.one(
                "SELECT * FROM versions WHERE doc_id=? AND seq=?",
                (doc_id, version_seq))
        if version is None:
            return self._fail("VERSION_NOT_FOUND",
                              f"版本不存在: seq={version_seq}",
                              **self._status_response(doc))
        content_row = self.store.one(
            "SELECT content FROM version_content WHERE version_id=?",
            (version["version_id"],))

        watermark = self._make_watermark(user, doc, version, now)
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO downloads(download_id, doc_id, version_seq,"
                " user_id, ts, watermark, content_hash) VALUES (?,?,?,?,?,?,?)",
                (_new_id("dld"), doc_id, version["seq"], actor, now,
                 watermark["id"], version["content_hash"]),
            )
            self._log(conn, actor, Action.DOWNLOAD_GRANTED, doc_id,
                      {"version_seq": version["seq"], "watermark": watermark["id"],
                       "sha256": version["content_hash"]})
        return self._ok(
            "DOWNLOAD_GRANTED",
            version_seq=version["seq"],
            sha256=version["content_hash"],
            watermark=watermark,
            content_b64=base64.b64encode(content_row["content"]).decode("ascii"),
            **self._status_response(doc),
        )

    @staticmethod
    def _make_watermark(user, doc, version, ts):
        stamp = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y%m%d%H%M%S")
        raw = f"{user['user_id']}|{doc['doc_id']}|v{version['seq']}|{ts}|{uuid.uuid4().hex}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        wm_id = f"WM-{digest[:16].upper()}"
        return {
            "id": wm_id,
            "text": (f"{wm_id} 下载人:{user['user_id']} 文档:{doc['doc_id']} "
                     f"版本:v{version['seq']} 时间:{stamp}Z"),
        }

    # ------------------------------------------------------------------
    # 查询：状态、审批队列、下载记录、审计事件、导出清单
    # ------------------------------------------------------------------
    def get_document_status(self, actor, doc_id):
        doc = self._get_doc(doc_id)
        if doc is None:
            return self._fail("DOCUMENT_NOT_FOUND", f"文档不存在: {doc_id}")
        payload = self._status_response(doc)
        if actor is not None:
            user = self._get_user(actor)
            if user is None:
                return self._fail("UNKNOWN_USER", f"用户不存在: {actor}")
            allowed, code, reason = self._evaluate_access(user, doc)
            payload["your_access"] = {
                "allowed": allowed, "code": code, "reason": reason or None,
                "your_clearance": self._level_info(user["clearance"]),
            }
        return self._ok(**payload)

    def approval_queue(self, actor=None):
        """待审批队列。指定 actor 时只返回其角色当前可处理的申请。"""
        rows = self.store.query(
            "SELECT * FROM change_requests WHERE status=? ORDER BY created_at",
            (RequestStatus.PENDING,),
        )
        role_filter = None
        if actor is not None:
            user = self._get_user(actor)
            if user is None:
                return self._fail("UNKNOWN_USER", f"用户不存在: {actor}")
            role_filter = self._user_roles(user)
        items = []
        for req in rows:
            detail = self._request_detail(req)
            node = detail["current_node"]
            if role_filter is not None and (
                    node is None or node["role"] not in role_filter):
                continue
            doc = self._get_doc(req["doc_id"])
            detail["doc_title"] = doc["title"]
            detail["current_classification"] = self._level_info(doc["current_level"])
            items.append(detail)
        return self._ok(queue=items, pending_count=len(items))

    def list_downloads(self, actor, doc_id):
        user = self._get_user(actor)
        if user is None:
            return self._fail("UNKNOWN_USER", f"用户不存在: {actor}")
        if not PRIVILEGED_AUDIT_ROLES & self._user_roles(user):
            return self._fail("FORBIDDEN", "只有保密管理员或审计员可以查看下载记录")
        doc = self._get_doc(doc_id)
        if doc is None:
            return self._fail("DOCUMENT_NOT_FOUND", f"文档不存在: {doc_id}")
        rows = self.store.query(
            "SELECT * FROM downloads WHERE doc_id=? ORDER BY ts", (doc_id,))
        return self._ok(
            downloads=[
                {"download_id": r["download_id"], "user_id": r["user_id"],
                 "version_seq": r["version_seq"], "ts": _iso(r["ts"]),
                 "watermark": r["watermark"], "sha256": r["content_hash"]}
                for r in rows
            ],
            **self._status_response(doc),
        )

    def list_events(self, actor, doc_id):
        user = self._get_user(actor)
        if user is None:
            return self._fail("UNKNOWN_USER", f"用户不存在: {actor}")
        if not PRIVILEGED_AUDIT_ROLES & self._user_roles(user):
            return self._fail("FORBIDDEN", "只有保密管理员或审计员可以查看审计事件")
        if self._get_doc(doc_id) is None:
            return self._fail("DOCUMENT_NOT_FOUND", f"文档不存在: {doc_id}")
        rows = self.store.query(
            "SELECT * FROM events WHERE doc_id=? ORDER BY ts, event_id", (doc_id,))
        return self._ok(
            events=[
                {"event_id": r["event_id"], "ts": _iso(r["ts"]),
                 "actor": r["actor"], "action": r["action"],
                 "detail": json.loads(r["detail"])}
                for r in rows
            ]
        )

    def export_manifest(self, actor):
        """导出清单：只含元数据与内容哈希，绝不包含正文。"""
        user = self._get_user(actor)
        if user is None:
            return self._fail("UNKNOWN_USER", f"用户不存在: {actor}")
        if not PRIVILEGED_AUDIT_ROLES & self._user_roles(user):
            return self._fail("FORBIDDEN", "只有保密管理员或审计员可以导出清单")
        docs = self.store.query("SELECT * FROM documents ORDER BY created_at")
        items = []
        for doc in docs:
            status = self._doc_status(doc)
            dl = self.store.one(
                "SELECT COUNT(*) AS c FROM downloads WHERE doc_id=?",
                (doc["doc_id"],))
            items.append({
                "doc_id": status["doc_id"],
                "title": status["title"],
                "owner_department": status["owner_department"],
                "current_classification": status["current_classification"],
                "pending_change": status["pending_change"],
                "versions": status["versions"],          # 仅 seq/sha256/大小等元数据
                "visible_scope": status["visible_scope"],
                "download_count": dl["c"],
            })
        with self.store.transaction() as conn:
            self._log(conn, actor, Action.MANIFEST_EXPORTED, None,
                      {"document_count": len(items)})
        return self._ok(manifest=items, document_count=len(items))


# 兼容骨架中的入口名
class Service(DocumentFlowService):
    """向后兼容的服务入口别名。"""
