"""SQLite 持久化层。

所有领域状态（文档、版本、变更申请、审批节点、授权、下载记录、审计事件）
都落在同一个 SQLite 库中；服务重启后重新打开同一文件即可恢复，
审批队列、授权有效期与访问事件保持一致。

正文内容单独存放在 version_content 表，导出清单等元数据查询不会触碰它。
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id     TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    department  TEXT NOT NULL,
    clearance   INTEGER NOT NULL,
    roles       TEXT NOT NULL          -- JSON 数组
);

CREATE TABLE IF NOT EXISTS documents (
    doc_id           TEXT PRIMARY KEY,
    title            TEXT NOT NULL,
    owner_department TEXT NOT NULL,
    created_by       TEXT NOT NULL,
    created_at       REAL NOT NULL,
    current_level    INTEGER NOT NULL  -- 当前生效密级；审批完成前不变
);

CREATE TABLE IF NOT EXISTS versions (
    version_id   TEXT PRIMARY KEY,
    doc_id       TEXT NOT NULL REFERENCES documents(doc_id),
    seq          INTEGER NOT NULL,
    content_hash TEXT NOT NULL,        -- sha256，用于重复上传识别
    size         INTEGER NOT NULL,
    uploaded_by  TEXT NOT NULL,
    uploaded_at  REAL NOT NULL,
    UNIQUE (doc_id, content_hash)
);
CREATE INDEX IF NOT EXISTS idx_versions_hash ON versions(content_hash);

-- 正文与元数据分离：清单/状态查询只读 versions，不读此表
CREATE TABLE IF NOT EXISTS version_content (
    version_id TEXT PRIMARY KEY REFERENCES versions(version_id),
    content    BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS change_requests (
    request_id   TEXT PRIMARY KEY,
    doc_id       TEXT NOT NULL REFERENCES documents(doc_id),
    proposer     TEXT NOT NULL,
    from_level   INTEGER NOT NULL,
    to_level     INTEGER NOT NULL,
    direction    TEXT NOT NULL,        -- upgrade / downgrade
    reason       TEXT NOT NULL,
    status       TEXT NOT NULL,        -- PENDING/EFFECTIVE/REJECTED/WITHDRAWN
    created_at   REAL NOT NULL,
    decided_at   REAL,
    reject_reason TEXT
);

CREATE TABLE IF NOT EXISTS approval_nodes (
    node_id    TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES change_requests(request_id),
    seq        INTEGER NOT NULL,       -- 审批顺序，从 1 开始
    role       TEXT NOT NULL,          -- 该节点要求的审批角色
    status     TEXT NOT NULL,          -- PENDING/APPROVED/REJECTED/SKIPPED
    actor      TEXT,
    acted_at   REAL,
    comment    TEXT
);
CREATE INDEX IF NOT EXISTS idx_nodes_request ON approval_nodes(request_id);

CREATE TABLE IF NOT EXISTS grants (
    grant_id     TEXT PRIMARY KEY,
    doc_id       TEXT NOT NULL REFERENCES documents(doc_id),
    subject_type TEXT NOT NULL,        -- user / department
    subject_id   TEXT NOT NULL,
    granted_by   TEXT NOT NULL,
    granted_at   REAL NOT NULL,
    expires_at   REAL,                 -- NULL 表示长期有效
    revoked_at   REAL,                 -- 撤销只置位，不删除，保留历史
    revoked_by   TEXT,
    revoke_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_grants_doc ON grants(doc_id);

CREATE TABLE IF NOT EXISTS downloads (
    download_id  TEXT PRIMARY KEY,
    doc_id       TEXT NOT NULL REFERENCES documents(doc_id),
    version_seq  INTEGER NOT NULL,
    user_id      TEXT NOT NULL,
    ts           REAL NOT NULL,
    watermark    TEXT NOT NULL,        -- 下载水印
    content_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_downloads_doc ON downloads(doc_id);

-- 审计事件：只追加，任何代码路径都不得 UPDATE/DELETE
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    ts       REAL NOT NULL,
    actor    TEXT NOT NULL,
    action   TEXT NOT NULL,
    doc_id   TEXT,
    detail   TEXT NOT NULL             -- JSON
);
CREATE INDEX IF NOT EXISTS idx_events_doc ON events(doc_id);
"""


class Store:
    """对 sqlite3 连接的薄封装：行工厂、写锁、事务。"""

    def __init__(self, path: str = ":memory:"):
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    @contextmanager
    def transaction(self):
        """多步写入在同一事务中提交，保证审批生效等操作的原子性。"""
        with self._lock:
            try:
                yield self.conn
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

    def query(self, sql, params=()):
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    def one(self, sql, params=()):
        with self._lock:
            return self.conn.execute(sql, params).fetchone()

    def close(self):
        with self._lock:
            self.conn.close()
