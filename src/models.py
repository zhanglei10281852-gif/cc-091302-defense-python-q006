"""领域模型与常量定义。

密级按有序枚举表示，变更只允许逐级（rank ±1）进行；
审批链按变更方向（升密/降密）分别配置，节点必须按序审批。
"""
from __future__ import annotations

from enum import IntEnum


class Level(IntEnum):
    """密级，数值越大密级越高。"""

    PUBLIC = 0
    INTERNAL = 1
    SECRET = 2
    CONFIDENTIAL = 3
    TOP_SECRET = 4


LEVEL_LABELS = {
    Level.PUBLIC: "公开",
    Level.INTERNAL: "内部",
    Level.SECRET: "秘密",
    Level.CONFIDENTIAL: "机密",
    Level.TOP_SECRET: "绝密",
}

# 默认审批链：按角色逐级审批。降密风险更高，多一级主管领导节点。
DEFAULT_APPROVAL_CHAINS = {
    "upgrade": ("dept_security_officer", "security_admin"),
    "downgrade": ("dept_security_officer", "security_admin", "director"),
}

ROLE_LABELS = {
    "staff": "普通人员",
    "dept_security_officer": "部门保密员",
    "security_admin": "保密管理员",
    "director": "主管领导",
    "auditor": "审计员",
}

# 可查看审计事件、下载记录与导出清单的角色
PRIVILEGED_AUDIT_ROLES = frozenset({"security_admin", "auditor"})
# 可分配/撤销阅知范围的角色
GRANT_MANAGER_ROLES = frozenset({"security_admin", "dept_security_officer"})


class RequestStatus:
    """密级变更申请状态。"""

    PENDING = "PENDING"        # 审批中
    EFFECTIVE = "EFFECTIVE"    # 审批完成并已生效
    REJECTED = "REJECTED"      # 被驳回
    WITHDRAWN = "WITHDRAWN"    # 申请人撤回


class NodeStatus:
    """审批节点状态。"""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    SKIPPED = "SKIPPED"  # 申请被驳回/撤回后，后续未处理节点


class Action:
    """审计事件类型。"""

    USER_REGISTERED = "USER_REGISTERED"
    DOC_CREATED = "DOC_CREATED"
    VERSION_UPLOADED = "VERSION_UPLOADED"
    VERSION_DEDUPED = "VERSION_DEDUPED"
    CHANGE_PROPOSED = "CHANGE_PROPOSED"
    CHANGE_APPROVED = "CHANGE_APPROVED"
    CHANGE_REJECTED = "CHANGE_REJECTED"
    CHANGE_WITHDRAWN = "CHANGE_WITHDRAWN"
    CHANGE_EFFECTIVE = "CHANGE_EFFECTIVE"
    GRANT_ASSIGNED = "GRANT_ASSIGNED"
    GRANT_REVOKED = "GRANT_REVOKED"
    DOWNLOAD_GRANTED = "DOWNLOAD_GRANTED"
    DOWNLOAD_DENIED = "DOWNLOAD_DENIED"
    MANIFEST_EXPORTED = "MANIFEST_EXPORTED"


def parse_level(value) -> Level:
    """把 int / 英文名 / 中文标签解析为 Level。"""
    if isinstance(value, Level):
        return value
    if isinstance(value, bool):
        raise ValueError(f"未知密级: {value!r}")
    if isinstance(value, int):
        return Level(value)
    if isinstance(value, str):
        text = value.strip()
        upper = text.upper()
        if upper in Level.__members__:
            return Level[upper]
        for level, label in LEVEL_LABELS.items():
            if text == label:
                return level
    raise ValueError(f"未知密级: {value!r}")
