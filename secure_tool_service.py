"""把结构化工具网关与一次性人工审批组合起来；当前不执行真实工具。"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from approval_manager import ApprovalError, ApprovalManager
from audit_log import HashChainAuditLog
from structured_tools import StructuredToolGateway, ToolDecision


class SecureToolService:
    def __init__(
        self,
        *,
        gateway: StructuredToolGateway | None = None,
        approvals: ApprovalManager | None = None,
        approval_store: Path | str | None = None,
        audit: HashChainAuditLog | None = None,
    ) -> None:
        self.gateway = gateway or StructuredToolGateway()
        if approvals is not None:
            self.approvals = approvals
        elif approval_store is not None:
            self.approvals = ApprovalManager(approval_store)
        else:
            self.approvals = ApprovalManager()
        self.audit = audit

    def _audit(self, event: str, payload: dict[str, Any]) -> None:
        if self.audit is not None:
            self.audit.append(event, payload)

    def check_call(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        role: str,
        llm_risk: str = "low",
    ) -> ToolDecision:
        decision = self.gateway.authorize(
            tool, arguments, role=role, llm_risk=llm_risk
        )
        self._audit(
            "tool_decision",
            {
                "tool": tool,
                "arguments": arguments,
                "role": role,
                "llm_risk": llm_risk,
                "decision": decision.decision,
                "effective_risk": decision.effective_risk,
                "call_digest": decision.call_digest,
                "reasons": list(decision.reasons),
            },
        )
        return decision

    def request_approval(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        requester: str,
        requester_role: str,
        reason: str,
        llm_risk: str = "low",
        ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        decision = self.check_call(
            tool, arguments, role=requester_role, llm_risk=llm_risk
        )
        if decision.decision != "require_human":
            raise ApprovalError(
                f"该调用当前决策为 {decision.decision}，不能创建审批申请"
            )
        request = self.approvals.create_request(
            tool=tool,
            arguments=arguments,
            call_digest=decision.call_digest,
            requester=requester,
            requester_role=requester_role,
            reason=reason,
            ttl_seconds=ttl_seconds,
        )
        self._audit(
            "approval_requested",
            {
                "request_id": request["request_id"],
                "tool": tool,
                "call_digest": decision.call_digest,
                "requester": requester,
                "requester_role": requester_role,
                "expires_at": request["expires_at"],
            },
        )
        return request

    def approve_request(
        self,
        request_id: str,
        *,
        approver: str,
        approver_role: str,
    ) -> dict[str, Any]:
        grant = self.approvals.approve(
            request_id, approver=approver, approver_role=approver_role
        )
        self._audit(
            "approval_granted",
            {
                "request_id": request_id,
                "tool": grant["tool"],
                "call_digest": grant["call_digest"],
                "approver": approver,
                "approver_role": approver_role,
                "expires_at": grant["expires_at"],
            },
        )
        return grant

    def authorize_with_token(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        role: str,
        llm_risk: str,
        request_id: str,
        approval_token: str,
    ) -> ToolDecision:
        preliminary = self.check_call(
            tool, arguments, role=role, llm_risk=llm_risk
        )
        if preliminary.decision == "deny":
            self._audit(
                "approved_call_rejected",
                {
                    "request_id": request_id,
                    "tool": tool,
                    "call_digest": preliminary.call_digest,
                    "reasons": list(preliminary.reasons),
                },
            )
            return preliminary
        if preliminary.decision == "allow":
            return preliminary

        try:
            approval = self.approvals.consume(
                request_id,
                approval_token,
                tool=tool,
                call_digest=preliminary.call_digest,
            )
        except ApprovalError as exc:
            decision = ToolDecision(
                tool=tool,
                decision="deny",
                tool_risk=preliminary.tool_risk,
                llm_risk=preliminary.llm_risk,
                effective_risk=preliminary.effective_risk,
                reasons=(str(exc),),
                call_digest=preliminary.call_digest,
            )
            self._audit(
                "approval_rejected",
                {
                    "request_id": request_id,
                    "tool": tool,
                    "call_digest": preliminary.call_digest,
                    "reason": str(exc),
                },
            )
            return decision
        decision = self.gateway.authorize(
            tool,
            arguments,
            role=role,
            llm_risk=llm_risk,
            approval=approval,
        )
        self._audit(
            "approval_consumed",
            {
                "request_id": request_id,
                "tool": tool,
                "call_digest": preliminary.call_digest,
                "decision": decision.decision,
            },
        )
        return decision


