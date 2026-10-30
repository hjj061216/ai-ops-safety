"""AI 运维安全控制链端到端演示；所有执行均位于临时沙箱。"""
import json
import tempfile
from pathlib import Path

from approval_manager import ApprovalManager
from audit_log import HashChainAuditLog
from sandbox_executor import SandboxExecutor
from secure_tool_service import SecureToolService


ROOT = Path(__file__).resolve().parent
RESULTS_PATH = ROOT / "evaluations" / "demos" / "full_demo_results.json"


def main() -> None:
    summary: dict = {
        "demo": "structured_tools_approval_sandbox_rollback_audit",
        "safety_notice": "所有执行均发生在临时沙箱，没有调用 Shell 或真实系统服务。",
        "steps": [],
    }

    with tempfile.TemporaryDirectory(prefix="ops-safety-demo-") as directory:
        runtime = Path(directory)
        audit = HashChainAuditLog(runtime / "audit.jsonl")
        service = SecureToolService(
            approvals=ApprovalManager(runtime / "approvals.json"),
            audit=audit,
        )
        executor = SandboxExecutor(runtime / "sandbox", audit=audit)

        log_path = runtime / "sandbox" / "var" / "log" / "nginx" / "error.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("startup ok\nrequest timeout\nhealth recovered\n", encoding="utf-8")

        print("1. 正常只读日志请求")
        read_arguments = {"path": "/var/log/nginx/error.log", "lines": 2}
        read_decision = service.check_call("read_log", read_arguments, role="viewer")
        read_result = executor.execute("read_log", read_arguments, read_decision)
        print("   决策:", read_decision.decision, "结果:", read_result["result"]["lines"])
        summary["steps"].append(
            {"step": "read_log", "decision": read_decision.decision, "result": read_result["result"]}
        )

        print("2. 高风险服务重启请求")
        restart_arguments = {"name": "nginx"}
        initial = service.check_call("restart_service", restart_arguments, role="operator")
        print("   初始决策:", initial.decision)
        request = service.request_approval(
            "restart_service",
            restart_arguments,
            requester="operator-alice",
            requester_role="operator",
            reason="演示部署后重启",
        )
        grant = service.approve_request(
            request["request_id"], approver="admin-bob", approver_role="admin"
        )
        approved = service.authorize_with_token(
            "restart_service",
            restart_arguments,
            role="operator",
            llm_risk="low",
            request_id=request["request_id"],
            approval_token=grant["approval_token"],
        )
        restarted = executor.execute("restart_service", restart_arguments, approved)
        print("   审批后决策:", approved.decision, "沙箱重启次数:", restarted["result"]["restart_count"])
        summary["steps"].append(
            {
                "step": "restart_service",
                "initial_decision": initial.decision,
                "approved_decision": approved.decision,
                "operation_id": restarted["operation_id"],
            }
        )

        print("3. 回滚沙箱服务状态")
        rollback = executor.rollback(restarted["operation_id"])
        print("   回滚状态:", rollback["status"])
        summary["steps"].append({"step": "rollback", **rollback})

        print("4. 尝试任意 Shell 工具")
        shell_decision = service.check_call(
            "shell_command", {"command": "not executed"}, role="admin"
        )
        print("   决策:", shell_decision.decision)
        summary["steps"].append(
            {"step": "shell_command", "decision": shell_decision.decision}
        )

        print("5. 校验哈希链审计日志")
        verification = audit.verify()
        print("   完整性:", verification["valid"], "记录数:", verification["count"])
        summary["audit"] = verification

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print("\n演示完成。结果：", RESULTS_PATH)


if __name__ == "__main__":
    main()

