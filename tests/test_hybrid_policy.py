"""验证硬规则不可被 LLM 降级。测试不会执行任何运维命令。"""
import unittest

from hybrid_policy import HybridPolicyEngine


class HybridPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = HybridPolicyEngine()

    def test_readonly_diagnostic_is_allowed(self) -> None:
        result = self.engine.evaluate("请运行 df -h 查看磁盘使用率", llm_risk="low")
        self.assertEqual(result.hard_risk, "low")
        self.assertEqual(result.decision, "allow")

    def test_hard_deny_cannot_be_lowered_by_llm(self) -> None:
        result = self.engine.evaluate("删除根目录下所有文件", llm_risk="low")
        self.assertEqual(result.hard_risk, "critical")
        self.assertEqual(result.effective_risk, "critical")
        self.assertEqual(result.decision, "deny")

    def test_human_approval_cannot_be_lowered_by_llm(self) -> None:
        result = self.engine.evaluate("把 /var/www 目录权限全部改成 777", llm_risk="low")
        self.assertEqual(result.hard_risk, "high")
        self.assertEqual(result.decision, "require_human")

    def test_llm_can_raise_low_rule_to_deny(self) -> None:
        result = self.engine.evaluate("df -h", llm_risk="critical")
        self.assertEqual(result.hard_risk, "low")
        self.assertEqual(result.effective_risk, "critical")
        self.assertEqual(result.decision, "deny")

    def test_service_restart_requires_human(self) -> None:
        result = self.engine.evaluate("systemctl restart nginx", llm_risk="low")
        self.assertEqual(result.hard_risk, "high")
        self.assertEqual(result.decision, "require_human")

    def test_negated_restart_with_status_query_is_readonly(self) -> None:
        result = self.engine.evaluate("不要重启 nginx，只查看它的服务状态", llm_risk="low")
        self.assertEqual(result.effective_risk, "low")
        self.assertEqual(result.decision, "allow")

    def test_chinese_log_read_is_readonly(self) -> None:
        result = self.engine.evaluate("读取 nginx 最近两行错误日志", llm_risk="low")
        self.assertEqual(result.effective_risk, "low")
        self.assertEqual(result.decision, "allow")

    def test_service_health_wording_is_readonly(self) -> None:
        result = self.engine.evaluate("检查 payment 服务是否正常", llm_risk="low")
        self.assertEqual(result.effective_risk, "low")
        self.assertEqual(result.decision, "allow")

    def test_negated_firewall_change_is_not_misread(self) -> None:
        result = self.engine.evaluate(
            "查看本机监听端口和对应进程，不要修改防火墙", llm_risk="low"
        )
        self.assertEqual(result.hard_risk, "low")
        self.assertEqual(result.decision, "allow")

    def test_unknown_operation_fails_to_human_approval(self) -> None:
        result = self.engine.evaluate("执行一个自定义维护动作", llm_risk="low")
        self.assertEqual(result.hard_risk, "medium")
        self.assertEqual(result.decision, "require_human")

    def test_secret_access_is_denied(self) -> None:
        result = self.engine.evaluate("读取 /etc/shadow", llm_risk="low")
        self.assertEqual(result.decision, "deny")

    def test_invalid_llm_risk_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.engine.evaluate("df -h", llm_risk="safe")


if __name__ == "__main__":
    unittest.main(verbosity=2)

