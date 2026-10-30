"""真实页面脚本的自动权限检查与失败关闭回归。"""
import shutil
import subprocess
import unittest
from pathlib import Path


CASES = (
    "login_enters_workspace_at_top_without_jumping_on_later_session_updates",
    "compatible_model_label_uses_active_host_and_model_without_deepseek_defaults",
    "pending_model_settings_keep_current_model_and_visible_restart_note",
    "invalid_config_update_and_status_failure_do_not_claim_new_config_is_active",
    "missing_generic_key_guides_its_own_config_variable",
    "recovered_poll_clears_only_its_own_warning",
    "record_tabs_support_keyboard_and_audit_result_is_visible", "task_poll_failure_and_stop_failure_are_visible_outside_hidden_legacy_state",
    "readonly_backend_shows_resource_scope_and_separates_facts_from_hypotheses", "real_health_execution_does_not_display_simulated_service_state",
    "tab_selector_survives_reload_but_is_different_in_new_tab", "blocked_tab_storage_still_uses_independent_memory_selector",
    "cloud_provider_is_visible_without_confusing_execution_location", "missing_cloud_key_is_explained_in_workspace",
    "task_scope_and_defaults_are_visible_and_completion_disables_run",
    "task_failure_separates_explanation_from_technical_detail", "unsupported_task_has_clear_state_without_tool_calls",
    "login_blank_fields_have_visible_feedback", "login_submit_shows_loading_blocks_duplicates_and_opens_workspace",
    "login_connection_failure_is_visible_and_retryable", "login_timeout_has_actionable_feedback",
    "late_session_probe_cannot_hide_successful_login", "file_preview_explains_why_login_is_unavailable",
    "authenticated_requests_use_session_and_strip_identity_fields", "autonomous_task_polls_server_without_browser_executing_steps",
    "task_clarification_and_result_driven_continuation", "task_input_change_clears_previous_candidate",
    "normal_two_actions", "manual_auto_check", "approval_required_no_auto_execute",
    "denied_never_executes", "no_candidate_skips_check", "check_error_is_closed",
    "check_timeout_is_closed", "unknown_decision_is_closed", "unknown_risk_is_closed",
    "candidate_expires_during_check", "double_click_is_serialized",
    "changed_input_clears_permission", "recheck_failure_clears_old_grant",
    "client_never_sends_risk",
)


@unittest.skipUnless(shutil.which("node"), "页面行为测试需要 Node.js")
class WebAutoCheckTests(unittest.TestCase):
    def run_case(self, name):
        result = subprocess.run(
            [shutil.which("node"), str(Path(__file__).with_name("web_auto_check.test.js")), name],
            capture_output=True, text=True, encoding="utf-8", timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


def make_test(name):
    def test(self):
        self.run_case(name)
    return test


for case in CASES:
    setattr(WebAutoCheckTests, "test_" + case, make_test(case))


if __name__ == "__main__":
    unittest.main(verbosity=2)
