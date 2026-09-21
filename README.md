# 敏感文档分级流转

国防安全业务的敏感文档分级流转服务：文档版本管理、密级逐级审批、阅知范围授权、
下载水印留痕、只增审计与崩溃恢复。仅依赖 Python 3.11 标准库。

## 运行

```bash
python3 -m src.service --host 127.0.0.1 --port 8080 --data-dir ./data
# 环境变量 HOST / PORT / DATA_DIR 同样生效
```

健康检查：`GET /health`。也可直接作为库使用：

```python
from src.service import DocumentFlowService

svc = DocumentFlowService("./data")
doc = svc.create_document("行动简报", b"正文", "alice", initial_level="内部")
```

## 密级与审批链

默认四级，rank 递增；每级有定密责任人（审批人）：

| rank | 密级 | 审批人 |
| --- | --- | --- |
| 1 | 公开 | sec-public |
| 2 | 内部 | sec-internal |
| 3 | 秘密 | sec-secret |
| 4 | 机密 | sec-topsecret |

* **升级逐级进入**：内部→机密须经「秘密」「机密」两个节点依次批准。
* **降级逐级离开**：机密→内部须经「机密」「秘密」两个节点依次释放。
* 任一节点可**驳回**，驳回必须填写理由；申请人/所有者可撤销申请。
* **审批完成前文档保持原密级、原权限**；旧版本始终可按其密级下载。
* 同一文档同时只允许一条待审批变更。

## HTTP 接口

正文以 `content`（UTF-8 文本）或 `content_base64` 提交。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/documents` | 创建文档（版本 v1，同内容全局复用 blob） |
| GET | `/documents` | 文档清单（仅元数据，**绝不含正文**） |
| GET | `/documents/{id}` | 文档详情：当前密级、待审批节点、拒绝理由、可见范围 |
| POST | `/documents/{id}/versions` | 上传新版本；**SHA-256 相同则识别为已有版本** |
| POST | `/documents/{id}/change-requests` | 提出密级变更（需 reason、target_level） |
| GET | `/documents/{id}/change-requests` | 该文档的变更申请列表 |
| GET | `/change-requests/{id}` | 申请详情（步骤链、当前待审批节点、拒绝理由） |
| POST | `/change-requests/{id}/approve` | 当前节点审批人批准 |
| POST | `/change-requests/{id}/reject` | 当前节点审批人驳回（必须带 reason） |
| POST | `/change-requests/{id}/cancel` | 申请人/所有者撤销申请 |
| POST | `/documents/{id}/grants` | 授权 `user:<账号>` 或 `dept:<部门>`，可设 `expires_at` |
| POST | `/documents/{id}/revoke` | 撤销授权，**新请求立即拒绝** |
| POST | `/documents/{id}/download` | 下载（body：`user`、可选 `dept`、`version`），返回水印 |
| GET | `/documents/{id}/events` | 该文档的全部访问/审批事件 |
| GET | `/export` | 导出全量清单（哈希指纹，不含正文） |
| GET | `/audit` | 只增审计日志（撤销/驳回后历史仍在） |

响应统一为 `{"ok": true, "data": ...}`；错误为 `{"ok": false, "error":
{"code", "message", "current_level", "pending_node", "visible_scope"}}`，
即在被拒绝的响应中同样明确当前密级、待审批节点与可见范围。

下载响应中的水印形如：

```
【密级:机密】bob@ops 2026-09-21T12:35:13+00:00 WM-doc-xxxx-v2-ab12cd34ef56
```

## 安全与持久化语义

* 正文按 SHA-256 内容寻址存放于 `data/blobs/`；清单、文档视图、审计、拒绝事件
  均不含正文字段，只有哈希指纹。
* 授权状态在每次访问时实时判定：撤销立即生效，到期自动失效；撤销记录与历史
  下载事件均保留（审计日志只增）。
* `data/state.json` 以临时文件 + fsync + 原子 rename 提交；`data/audit.jsonl`
  只增且每行 fsync。重启后审批队列、授权有效期、访问事件与崩溃前一致；
  若崩溃发生在状态提交之后、审计落盘之前，重启时按状态事件补齐审计行
  （标记 `recovered: true`）。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

覆盖：内容去重、逐级升降审批、错误审批人拒绝、驳回理由、审批期间旧权限不变、
部门/个人授权与有效期、撤销即时生效且审计不丢、水印身份信息、导出不泄露正文、
重启恢复（含审计补齐）以及完整 HTTP 链路。
