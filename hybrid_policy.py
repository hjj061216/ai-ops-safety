"""YAML 硬规则与 LLM 风险的组合器。本模块不执行任何操作命令。"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parent
DEFAULT_POLICY_PATH = ROOT / "policy" / "hard_rules.yml"


@dataclass(frozen=True)
class PolicyResult:
    hard_risk: str
    llm_risk: str
    effective_risk: str
    decision: str
    matched_rules: tuple[str, ...]
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["matched_rules"] = list(self.matched_rules)
        data["reasons"] = list(self.reasons)
        return data


class HybridPolicyEngine:
    """硬规则先给出风险下限，LLM 只能把最终风险继续提高。"""

    def __init__(self, policy_path: Path | str = DEFAULT_POLICY_PATH) -> None:
        self.policy_path = Path(policy_path)
        self.policy = yaml.safe_load(self.policy_path.read_text(encoding="utf-8"))
        self.risk_order: dict[str, int] = self.policy["risk_order"]
        self.decision_by_risk: dict[str, str] = self.policy["decision_by_risk"]
        self.rules = []
        for rule in self.policy["rules"]:
            compiled = tuple(re.compile(pattern) for pattern in rule["patterns"])
            exclusions = tuple(
                re.compile(pattern) for pattern in rule.get("exclude_patterns", [])
            )
            self.rules.append((rule, compiled, exclusions))
        self._validate()

    def _validate(self) -> None:
        expected = set(self.risk_order)
        if set(self.decision_by_risk) != expected:
            raise ValueError("decision_by_risk must define every risk level")
        if self.policy["default"]["risk"] not in expected:
            raise ValueError("default risk is not defined in risk_order")
        for rule, _, _ in self.rules:
            if rule["risk"] not in expected:
                raise ValueError(f"unknown risk in rule {rule['id']}")

    def _max_risk(self, *risks: str) -> str:
        for risk in risks:
            if risk not in self.risk_order:
                raise ValueError(f"unknown risk level: {risk}")
        return max(risks, key=self.risk_order.__getitem__)

    def evaluate_hard_rules(self, text: str) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
        matches: list[dict[str, Any]] = []
        for rule, patterns, exclusions in self.rules:
            excluded = any(pattern.search(text) for pattern in exclusions)
            if not excluded and any(pattern.search(text) for pattern in patterns):
                matches.append(rule)

        if not matches:
            default = self.policy["default"]
            return default["risk"], (), (default["reason"],)

        highest = max(
            (rule["risk"] for rule in matches),
            key=self.risk_order.__getitem__,
        )
        highest_matches = [rule for rule in matches if rule["risk"] == highest]
        return (
            highest,
            tuple(rule["id"] for rule in highest_matches),
            tuple(rule["description"] for rule in highest_matches),
        )

    def evaluate(self, text: str, llm_risk: str = "low") -> PolicyResult:
        hard_risk, matched_rules, reasons = self.evaluate_hard_rules(text)
        effective_risk = self._max_risk(hard_risk, llm_risk)
        return PolicyResult(
            hard_risk=hard_risk,
            llm_risk=llm_risk,
            effective_risk=effective_risk,
            decision=self.decision_by_risk[effective_risk],
            matched_rules=matched_rules,
            reasons=reasons,
        )


if __name__ == "__main__":
    engine = HybridPolicyEngine()
    examples = (
        ("df -h", "low"),
        ("把 /var/www 递归改成 chmod 777", "low"),
        ("查看磁盘使用率", "critical"),
        ("删除根目录下所有文件", "low"),
    )
    for request, llm_risk in examples:
        result = engine.evaluate(request, llm_risk=llm_risk)
        print(request, "=>", result.to_dict())

