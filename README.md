# 敏感文档分级流转

该项目服务于国防安全业务，负责敏感文档分级流转相关信息的规范化处理与留痕。

运行环境：Python 3.11（仅依赖标准库）。代码位于 `src` 目录，配置与数据文件应按部署环境提供。

## 能力概览

- **文档与版本**：创建文档、上传新版本；重复上传同一内容按 SHA-256 识别为已有版本，并提示同一内容还保存在哪些文档中。
- **密级变更**：密级按 `公开 < 内部 < 秘密 < 机密 < 绝密` 排序，只能逐级升降；升密两级审批、降密三级审批（可在 `DEFAULT_APPROVAL_CHAINS` 配置）。审批未完成时，旧版本仍按原权限提供；终审通过后新密级在同一事务内生效。
- **阅知范围**：按用户或部门分配授权，支持有效期；撤销立即生效，新请求一律拒绝，历史授权与审计事件全部保留。
- **下载水印**：每次成功下载生成 `WM-` 水印并记录下载人、版本、时间与内容哈希，供审计追溯。
- **导出清单**：只含元数据与内容哈希，不包含正文（正文单独存于 `version_content` 表）。
- **恢复一致性**：全部状态落 SQLite，服务重启后审批队列、授权有效期、访问事件保持一致。

## 接口响应约定

所有接口返回统一信封：

```json
{"ok": true, "code": "OK", "reason": null, "...": "业务数据"}
```

文档相关响应携带 `document` 状态块，明确四项关键信息：

| 字段 | 含义 |
| --- | --- |
| `document.current_classification` | 当前生效密级（level/label/rank） |
| `document.pending_change.current_node` | 待审批节点（序号、要求角色）及完整节点列表 |
| `reason` | 拒绝理由（如 `CLEARANCE_INSUFFICIENT`、`GRANT_REVOKED`） |
| `document.visible_scope` | 可见范围：有效授权与已撤销授权留痕 |

## 运行

```bash
# 启动 HTTP 服务（JSON 接口）
python3 -m src.api --db /var/lib/docflow/service.db --port 8080

# 运行测试
python3 -m unittest discover -s tests -v
```

主要路由：`POST /users`、`POST /documents`、`POST /documents/{id}/versions`、`POST /documents/{id}/classification-changes`、`POST /classification-changes/{id}/approve|reject|withdraw`、`POST /documents/{id}/grants`、`POST /grants/{id}/revoke`、`POST /documents/{id}/download`、`GET /documents/{id}`、`GET /approval-queue`、`GET /documents/{id}/events|downloads`、`GET /manifest`。

## 代码结构

- `src/models.py` — 密级枚举、审批链、状态与事件常量
- `src/storage.py` — SQLite 持久化（正文与元数据分表）
- `src/service.py` — 领域服务 `DocumentFlowService`
- `src/api.py` — HTTP JSON 接口层
- `tests/` — 端到端测试（含持久化恢复、撤销留痕、清单防泄露）
