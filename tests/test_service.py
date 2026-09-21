"""文档分级流转服务的端到端测试（stdlib unittest）。

运行：python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.service import DocumentFlowService  # noqa: E402

CONTENT_V1 = b"action-briefing-content-v1"
CONTENT_V2 = b"action-briefing-content-v2"


class Base(unittest.TestCase):
    def setUp(self):
        self.now = [1_700_000_000.0]  # 可推进的假时钟
        self.svc = DocumentFlowService(":memory:", clock=lambda: self.now[0])
        # 用户目录：不同密级、不同角色
        self.svc.register_user("admin", "保密管理员", "保密办", "TOP_SECRET",
                               ["security_admin"])
        self.svc.register_user("auditor", "审计员", "审计处", "SECRET",
                               ["auditor"])
        self.svc.register_user("officer_a", "部门保密员A", "一部", "CONFIDENTIAL",
                               ["dept_security_officer"])
        self.svc.register_user("director", "主管领导", "机关", "TOP_SECRET",
                               ["director"])
        self.svc.register_user("alice", "爱丽丝", "一部", "SECRET", ["staff"])
        self.svc.register_user("bob", "鲍勃", "二部", "INTERNAL", ["staff"])
        self.svc.register_user("carol", "卡罗尔", "一部", "INTERNAL", ["staff"])

    def make_doc(self, level="SECRET", content=CONTENT_V1, title="行动简报"):
        resp = self.svc.create_document("officer_a", title, "一部", level, content)
        self.assertTrue(resp["ok"], resp)
        return resp["doc_id"]

    def grant(self, doc_id, subject, subject_type="user", expires_at=None):
        return self.svc.assign_grant("admin", doc_id, subject_type, subject,
                                     expires_at)


class TestVersions(Base):
    def test_create_document_and_status_block(self):
        doc_id = self.make_doc()
        resp = self.svc.get_document_status("alice", doc_id)
        self.assertTrue(resp["ok"])
        doc = resp["document"]
        self.assertEqual(doc["current_classification"]["level"], "SECRET")
        self.assertEqual(doc["current_classification"]["label"], "秘密")
        self.assertIsNone(doc["pending_change"])
        self.assertEqual(len(doc["versions"]), 1)
        self.assertIn("visible_scope", doc)
        # 状态接口不得返回正文
        self.assertNotIn("content", resp)
        self.assertNotIn("content_b64", resp)

    def test_duplicate_upload_recognized_as_existing_version(self):
        doc_id = self.make_doc()
        resp = self.svc.upload_version("alice", doc_id, CONTENT_V1)
        self.assertTrue(resp["ok"])
        self.assertEqual(resp["code"], "DUPLICATE_CONTENT")
        self.assertTrue(resp["deduplicated"])
        self.assertEqual(resp["version"]["seq"], 1)
        # 版本数不变
        status = self.svc.get_document_status("alice", doc_id)
        self.assertEqual(len(status["document"]["versions"]), 1)

    def test_new_content_creates_new_version(self):
        doc_id = self.make_doc()
        resp = self.svc.upload_version("alice", doc_id, CONTENT_V2)
        self.assertTrue(resp["ok"])
        self.assertEqual(resp["code"], "VERSION_CREATED")
        self.assertEqual(resp["version"]["seq"], 2)
        status = self.svc.get_document_status("alice", doc_id)
        self.assertEqual(len(status["document"]["versions"]), 2)

    def test_same_content_in_other_document_flagged(self):
        doc_a = self.make_doc(title="简报-一部")
        resp = self.svc.create_document("admin", "简报-二部", "二部",
                                        "INTERNAL", CONTENT_V1)
        self.assertTrue(resp["ok"])
        # 同一份简报被不同部门保存：响应中可发现重复
        self.assertIn(doc_a, resp["also_in_documents"])


class TestClassificationChange(Base):
    def test_non_stepwise_change_rejected(self):
        doc_id = self.make_doc("SECRET")
        resp = self.svc.propose_classification_change("officer_a", doc_id,
                                                      "PUBLIC", "想跳级")
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["code"], "NON_STEPWISE")
        self.assertIn("逐级", resp["reason"])
        allowed = {t["level"] for t in resp["allowed_targets"]}
        self.assertEqual(allowed, {"INTERNAL", "CONFIDENTIAL"})

    def test_same_level_rejected(self):
        doc_id = self.make_doc("SECRET")
        resp = self.svc.propose_classification_change("officer_a", doc_id,
                                                      "SECRET")
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["code"], "SAME_LEVEL")

    def test_pending_request_blocks_new_request(self):
        doc_id = self.make_doc("SECRET")
        r1 = self.svc.propose_classification_change("officer_a", doc_id,
                                                    "CONFIDENTIAL", "提级")
        self.assertTrue(r1["ok"])
        r2 = self.svc.propose_classification_change("admin", doc_id,
                                                    "INTERNAL", "再提一个")
        self.assertFalse(r2["ok"])
        self.assertEqual(r2["code"], "CHANGE_PENDING")
        # 响应中明确待审批节点
        self.assertEqual(r2["pending_request"]["current_node"]["seq"], 1)
        self.assertEqual(r2["pending_request"]["current_node"]["role"],
                         "dept_security_officer")

    def test_approval_chain_order_and_effect(self):
        doc_id = self.make_doc("SECRET")
        req = self.svc.propose_classification_change("officer_a", doc_id,
                                                     "CONFIDENTIAL", "提级")
        req_id = req["request"]["request_id"]

        # 越级审批：admin 不是第 1 节点角色
        bad = self.svc.approve_change("admin", req_id)
        self.assertFalse(bad["ok"])
        self.assertEqual(bad["code"], "WRONG_APPROVER")
        self.assertIn("dept_security_officer", bad["reason"])

        # 申请人不能批自己的申请
        self_appr = self.svc.approve_change("officer_a", req_id)
        self.assertFalse(self_appr["ok"])
        self.assertEqual(self_appr["code"], "SELF_APPROVAL")

        # 换一个部门保密员也不行（同角色但本人是申请人）——用 admin 链外角色仍不行
        # 第 1 节点：需要 dept_security_officer，officer_a 是申请人，注册另一个保密员
        self.svc.register_user("officer_b", "部门保密员B", "二部", "CONFIDENTIAL",
                               ["dept_security_officer"])
        ok1 = self.svc.approve_change("officer_b", req_id, "同意")
        self.assertTrue(ok1["ok"], ok1)
        # 一级通过后密级仍未变（还有第 2 节点）
        self.assertEqual(
            ok1["document"]["current_classification"]["level"], "SECRET")
        self.assertEqual(ok1["request"]["current_node"]["role"], "security_admin")

        ok2 = self.svc.approve_change("admin", req_id, "同意提级")
        self.assertTrue(ok2["ok"], ok2)
        self.assertEqual(ok2["request"]["status"], "EFFECTIVE")
        self.assertEqual(
            ok2["document"]["current_classification"]["level"], "CONFIDENTIAL")
        self.assertIsNone(ok2["document"]["pending_change"])

    def test_downgrade_chain_has_three_nodes(self):
        doc_id = self.make_doc("SECRET")
        req = self.svc.propose_classification_change("officer_a", doc_id,
                                                     "INTERNAL", "降密")
        roles = [n["role"] for n in req["request"]["nodes"]]
        self.assertEqual(roles,
                         ["dept_security_officer", "security_admin", "director"])

    def test_reject_records_reason_and_keeps_level(self):
        doc_id = self.make_doc("SECRET")
        req = self.svc.propose_classification_change("officer_a", doc_id,
                                                     "INTERNAL", "降密")
        req_id = req["request"]["request_id"]
        self.svc.register_user("officer_b", "部门保密员B", "二部", "CONFIDENTIAL",
                               ["dept_security_officer"])
        resp = self.svc.reject_change("officer_b", req_id, "不符合降密条件")
        self.assertTrue(resp["ok"])
        self.assertEqual(resp["request"]["status"], "REJECTED")
        self.assertEqual(resp["request"]["reject_reason"], "不符合降密条件")
        # 后续节点被跳过，密级不变
        self.assertEqual(resp["request"]["nodes"][-1]["status"], "SKIPPED")
        self.assertEqual(
            resp["document"]["current_classification"]["level"], "SECRET")
        # 已终结的申请不能再审批
        again = self.svc.approve_change("admin", req_id)
        self.assertFalse(again["ok"])
        self.assertEqual(again["code"], "NOT_PENDING")

    def test_withdraw_by_proposer_only(self):
        doc_id = self.make_doc("SECRET")
        req = self.svc.propose_classification_change("officer_a", doc_id,
                                                     "CONFIDENTIAL", "提级")
        req_id = req["request"]["request_id"]
        bad = self.svc.withdraw_change("admin", req_id)
        self.assertFalse(bad["ok"])
        ok = self.svc.withdraw_change("officer_a", req_id)
        self.assertTrue(ok["ok"])
        self.assertEqual(ok["request"]["status"], "WITHDRAWN")

    def test_old_permission_applies_while_upgrade_pending(self):
        """升密审批未完成时，旧版本仍按原（较低）权限提供。"""
        doc_id = self.make_doc("INTERNAL")
        self.grant(doc_id, "carol")  # carol  clearance=INTERNAL
        req = self.svc.propose_classification_change("officer_a", doc_id,
                                                     "SECRET", "提级")
        self.assertTrue(req["ok"])
        # 审批中：carol 仍可按 INTERNAL 权限下载
        dl = self.svc.download("carol", doc_id)
        self.assertTrue(dl["ok"], dl)
        # 完成审批链后：carol 密级不足，立即被拒
        self.svc.register_user("officer_b", "部门保密员B", "二部", "CONFIDENTIAL",
                               ["dept_security_officer"])
        self.svc.approve_change("officer_b", req["request"]["request_id"])
        self.svc.approve_change("admin", req["request"]["request_id"])
        denied = self.svc.download("carol", doc_id)
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["code"], "CLEARANCE_INSUFFICIENT")

    def test_old_permission_applies_while_downgrade_pending(self):
        """降密审批未完成时，仍按原（较高）权限管控。"""
        doc_id = self.make_doc("SECRET")
        self.grant(doc_id, "carol")
        req = self.svc.propose_classification_change("officer_a", doc_id,
                                                     "INTERNAL", "降密")
        # 审批中：carol（INTERNAL）仍不能下载
        denied = self.svc.download("carol", doc_id)
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["code"], "CLEARANCE_INSUFFICIENT")
        # 走完降密三级审批后放行
        self.svc.register_user("officer_b", "部门保密员B", "二部", "CONFIDENTIAL",
                               ["dept_security_officer"])
        rid = req["request"]["request_id"]
        self.svc.approve_change("officer_b", rid)
        self.svc.approve_change("admin", rid)
        self.svc.approve_change("director", rid)
        ok = self.svc.download("carol", doc_id)
        self.assertTrue(ok["ok"], ok)


class TestGrantsAndDownload(Base):
    def test_download_requires_scope_and_clearance(self):
        doc_id = self.make_doc("SECRET")
        # 无授权
        r1 = self.svc.download("alice", doc_id)
        self.assertFalse(r1["ok"])
        self.assertEqual(r1["code"], "NOT_IN_SCOPE")
        # 有授权但密级不足（bob 是 INTERNAL）
        self.grant(doc_id, "bob")
        r2 = self.svc.download("bob", doc_id)
        self.assertFalse(r2["ok"])
        self.assertEqual(r2["code"], "CLEARANCE_INSUFFICIENT")
        # 拒绝响应里也要带当前密级与可见范围
        self.assertEqual(
            r2["document"]["current_classification"]["level"], "SECRET")
        self.assertIn("visible_scope", r2["document"])
        self.assertEqual(r2["reason"], r2["reason"])  # reason 非空
        self.assertTrue(r2["reason"])

    def test_download_success_records_watermark(self):
        doc_id = self.make_doc("SECRET")
        self.grant(doc_id, "alice")
        resp = self.svc.download("alice", doc_id)
        self.assertTrue(resp["ok"], resp)
        wm = resp["watermark"]
        self.assertTrue(wm["id"].startswith("WM-"))
        self.assertIn("alice", wm["text"])
        # 下载记录可供审计查询：谁、何时、哪个版本、什么水印
        records = self.svc.list_downloads("admin", doc_id)
        self.assertTrue(records["ok"])
        self.assertEqual(len(records["downloads"]), 1)
        self.assertEqual(records["downloads"][0]["user_id"], "alice")
        self.assertEqual(records["downloads"][0]["watermark"], wm["id"])
        # 审计事件同步留痕
        events = self.svc.list_events("auditor", doc_id)
        actions = [e["action"] for e in events["events"]]
        self.assertIn("DOWNLOAD_GRANTED", actions)

    def test_department_grant_covers_member(self):
        doc_id = self.make_doc("INTERNAL")
        self.grant(doc_id, "一部", subject_type="department")
        resp = self.svc.download("carol", doc_id)
        self.assertTrue(resp["ok"], resp)

    def test_expired_grant_denied(self):
        doc_id = self.make_doc("INTERNAL")
        resp = self.grant(doc_id, "carol", expires_at=self.now[0] + 3600)
        self.assertTrue(resp["ok"], resp)
        self.now[0] += 7200  # 推进时钟，授权过期
        denied = self.svc.download("carol", doc_id)
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["code"], "GRANT_EXPIRED")

    def test_past_expiry_rejected(self):
        doc_id = self.make_doc("INTERNAL")
        resp = self.grant(doc_id, "carol", expires_at=self.now[0] - 1)
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["code"], "INVALID_EXPIRY")

    def test_revoke_denies_immediately_but_keeps_history(self):
        doc_id = self.make_doc("SECRET")
        grant = self.grant(doc_id, "alice")
        grant_id = grant["grant_id"]
        ok = self.svc.download("alice", doc_id)
        self.assertTrue(ok["ok"])
        watermark_before = ok["watermark"]["id"]

        rev = self.svc.revoke_grant("admin", grant_id, "岗位调整")
        self.assertTrue(rev["ok"])
        # 新请求立即拒绝
        denied = self.svc.download("alice", doc_id)
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["code"], "GRANT_REVOKED")
        self.assertIn("撤销", denied["reason"])
        # 历史审计不被抹掉：下载记录与事件都还在
        records = self.svc.list_downloads("admin", doc_id)
        self.assertEqual(len(records["downloads"]), 1)
        self.assertEqual(records["downloads"][0]["watermark"], watermark_before)
        events = self.svc.list_events("admin", doc_id)
        actions = [e["action"] for e in events["events"]]
        self.assertIn("DOWNLOAD_GRANTED", actions)
        self.assertIn("GRANT_REVOKED", actions)
        # 可见范围里保留已撤销授权的留痕
        scope = denied["document"]["visible_scope"]
        self.assertEqual(len(scope["revoked_grants"]), 1)
        self.assertEqual(scope["revoked_grants"][0]["revoke_reason"], "岗位调整")
        # 重复撤销返回明确错误
        again = self.svc.revoke_grant("admin", grant_id)
        self.assertFalse(again["ok"])
        self.assertEqual(again["code"], "ALREADY_REVOKED")

    def test_grant_management_forbidden_for_staff(self):
        doc_id = self.make_doc("INTERNAL")
        resp = self.svc.assign_grant("carol", doc_id, "user", "bob")
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["code"], "FORBIDDEN")

    def test_duplicate_active_grant_returns_existing(self):
        doc_id = self.make_doc("INTERNAL")
        first = self.grant(doc_id, "carol")
        second = self.grant(doc_id, "carol")
        self.assertTrue(second["ok"])
        self.assertEqual(second["code"], "GRANT_EXISTS")
        self.assertEqual(second["grant_id"], first["grant_id"])

    def test_audit_endpoints_privileged_only(self):
        doc_id = self.make_doc("SECRET")
        self.assertFalse(self.svc.list_events("alice", doc_id)["ok"])
        self.assertFalse(self.svc.list_downloads("alice", doc_id)["ok"])
        self.assertTrue(self.svc.list_events("auditor", doc_id)["ok"])


class TestManifest(Base):
    def _assert_no_content(self, obj):
        """递归断言响应中不含正文字段与正文内容。"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                self.assertNotIn("content", key.lower())
                self.assertNotIn("body", key.lower())
                self._assert_no_content(value)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                self._assert_no_content(item)
        elif isinstance(obj, (bytes, str)):
            self.assertNotIn(CONTENT_V1.decode(), obj if isinstance(obj, str)
                             else obj.decode("latin1"))

    def test_manifest_contains_metadata_but_no_content(self):
        doc_id = self.make_doc()
        self.grant(doc_id, "alice")
        self.svc.download("alice", doc_id)
        resp = self.svc.export_manifest("admin")
        self.assertTrue(resp["ok"])
        self.assertEqual(resp["document_count"], 1)
        item = resp["manifest"][0]
        self.assertEqual(item["doc_id"], doc_id)
        self.assertEqual(item["current_classification"]["level"], "SECRET")
        self.assertEqual(item["download_count"], 1)
        self.assertEqual(len(item["versions"]), 1)
        self.assertIn("sha256", item["versions"][0])
        self.assertEqual(len(item["visible_scope"]["active_grants"]), 1)
        self._assert_no_content(resp)

    def test_manifest_forbidden_for_staff(self):
        self.make_doc()
        resp = self.svc.export_manifest("alice")
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["code"], "FORBIDDEN")


class TestPersistence(Base):
    def test_state_consistent_after_restart(self):
        """服务恢复后：审批队列、授权有效期、访问事件保持一致。"""
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "service.db")
            now = [1_700_000_000.0]
            svc1 = DocumentFlowService(db, clock=lambda: now[0])
            svc1.register_user("admin", "保密管理员", "保密办", "TOP_SECRET",
                               ["security_admin"])
            svc1.register_user("officer_b", "部门保密员B", "二部", "CONFIDENTIAL",
                               ["dept_security_officer"])
            svc1.register_user("alice", "爱丽丝", "一部", "SECRET", ["staff"])
            doc = svc1.create_document("admin", "行动简报", "一部", "SECRET",
                                       CONTENT_V1)
            doc_id = doc["doc_id"]
            # 待审批的变更（停在第 1 节点）
            req = svc1.propose_classification_change("admin", doc_id,
                                                     "CONFIDENTIAL", "提级")
            req_id = req["request"]["request_id"]
            # 有时效的授权 + 一次下载 + 一次撤销
            svc1.assign_grant("admin", doc_id, "user", "alice",
                              expires_at=now[0] + 3600)
            svc1.download("alice", doc_id)
            g2 = svc1.assign_grant("admin", doc_id, "department", "二部")
            svc1.revoke_grant("admin", g2["grant_id"], "测试撤销")
            events_before = svc1.list_events("admin", doc_id)["events"]
            queue_before = svc1.approval_queue("officer_b")["queue"]
            svc1.store.close()

            # 模拟服务恢复：同一数据文件、同一时钟
            svc2 = DocumentFlowService(db, clock=lambda: now[0])
            queue_after = svc2.approval_queue("officer_b")["queue"]
            self.assertEqual([q["request_id"] for q in queue_after],
                             [q["request_id"] for q in queue_before])
            self.assertEqual(queue_after[0]["current_node"]["role"],
                             "dept_security_officer")
            # 授权有效期一致：alice 的授权未过期仍可下载
            dl = svc2.download("alice", doc_id)
            self.assertTrue(dl["ok"], dl)
            # 推进时钟超过有效期后拒绝
            now[0] += 7200
            expired = svc2.download("alice", doc_id)
            self.assertFalse(expired["ok"])
            self.assertEqual(expired["code"], "GRANT_EXPIRED")
            # 访问事件一致（恢复后只新增了 alice 的一次下载与一次拒绝）
            events_after = svc2.list_events("admin", doc_id)["events"]
            self.assertEqual(len(events_after), len(events_before) + 2)
            actions = [e["action"] for e in events_after]
            self.assertIn("GRANT_REVOKED", actions)
            self.assertIn("DOWNLOAD_GRANTED", actions)
            # 审批可在恢复后继续推进并生效
            svc2.approve_change("officer_b", req_id)
            svc2.register_user("admin2", "保密管理员2", "保密办", "TOP_SECRET",
                               ["security_admin"])
            done = svc2.approve_change("admin2", req_id)
            self.assertEqual(
                done["document"]["current_classification"]["level"],
                "CONFIDENTIAL")
            svc2.store.close()


if __name__ == "__main__":
    unittest.main()
