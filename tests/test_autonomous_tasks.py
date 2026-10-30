import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock

from auth import PermissionDenied, AuthenticationError
from local_app import LocalSafetyApp


def action(tool=None, arguments=None, status="propose", risk="low"):
    return {"status":status,"message":"检查下一步" if tool else "根据执行结果总结", "plan":["检查服务","检查日志","总结"],"tool":tool,"arguments":arguments or {},"risk":risk}


class AutonomousTaskTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = LocalSafetyApp(Path(self.temp.name))
        for name,role in (("alice","operator"),("bob","approver"),("erin","operator")):
            self.app.auth.add_user(name,"synthetic-long-password",role)

    def tearDown(self):
        self.app.tasks.stop_for_owner("alice")
        for task in self.app.tasks.tasks.values():
            worker = task["worker"]
            if worker:
                worker.join(3)
        self.temp.cleanup()

    @contextmanager
    def as_user(self, name):
        token = self.app.identity.set(self.app.auth.principal(name))
        try:
            yield
        finally:
            self.app.identity.reset(token)

    def wait(self, task_id, expected):
        for _ in range(150):
            with self.as_user("alice"):
                result = self.app.task_state(task_id)
            if result["runner_state"] in expected:
                return result
            time.sleep(.02)
        self.fail("Task did not reach expected state: "+str(result))

    def test_read_only_steps_run_without_per_step_clicks(self):
        self.app.tasks.planner.suggest = Mock(side_effect=[action("get_service_status",{"name":"nginx"}),action("read_log",{"path":"/var/log/nginx/error.log","lines":2}),action(status="complete")])
        with self.as_user("alice"):
            task = self.app.task_start({"request":"排查 nginx 异常","autonomy":"read_only"})
            self.assertEqual(task["effective_risk"], "low")
            self.app.task_run({"task_id":task["task_id"]})
        final = self.wait(task["task_id"], {"complete","blocked"})
        self.assertEqual(final["runner_state"], "complete", final)
        self.assertEqual(final["steps_completed"], 2)
        self.assertEqual(self.app.approvals.list_public_records(), [])
        with self.as_user("erin"), self.assertRaises(PermissionDenied):
            self.app.task_run({"task_id":task["task_id"]})

    def test_mutation_pauses_independent_approval_then_resumes_and_verifies(self):
        self.app.tasks.planner.suggest = Mock(side_effect=[action("get_service_status",{"name":"nginx"}),action("restart_service",{"name":"nginx"},risk="high"),action("get_service_status",{"name":"nginx"}),action(status="complete")])
        with self.as_user("alice"):
            task = self.app.task_start({"request":"先检查 nginx 状态，然后重启 nginx，再检查状态","autonomy":"read_only"})
            self.app.task_run({"task_id":task["task_id"]})
        waiting = self.wait(task["task_id"], {"waiting_approval","blocked"})
        self.assertEqual(waiting["runner_state"], "waiting_approval", waiting)
        self.assertEqual(len(self.app.executor.list_operations()), 1)
        request_id = waiting["approval_request_id"]
        with self.as_user("bob"):
            grant = self.app.approve({"request_id":request_id})
            self.assertNotIn("approval_token", grant)
        final = self.wait(task["task_id"], {"complete","blocked"})
        self.assertEqual(final["runner_state"], "complete", final)
        self.assertEqual(final["steps_completed"], 3)
        self.assertEqual(final["observations"][-1]["facts"]["status"], "running")

    def test_model_medium_risk_pauses_even_for_read_only_tools(self):
        self.app.tasks.planner.suggest = Mock(return_value=action("get_service_status",{"name":"nginx"},risk="medium"))
        with self.as_user("alice"):
            task = self.app.task_start({"request":"排查 nginx 异常","autonomy":"read_only"})
            self.app.task_run({"task_id":task["task_id"]})
        final = self.wait(task["task_id"], {"waiting_approval","blocked"})
        self.assertEqual(final["runner_state"], "waiting_approval")
        self.assertEqual(self.app.executor.list_operations(), [])

    def test_stop_during_planning_prevents_next_execution(self):
        entered, release = threading.Event(), threading.Event()
        def next_step(*args):
            entered.set(); release.wait(2)
            return action("read_log",{"path":"/var/log/nginx/error.log","lines":2})
        self.app.tasks.planner.suggest = Mock(side_effect=[action("get_service_status",{"name":"nginx"}),next_step])
        # Mock.side_effect returns callables as values; use explicit dispatch.
        counter = iter([action("get_service_status",{"name":"nginx"})])
        first = True
        def planner(*args):
            nonlocal first
            if first:
                first=False; return next(counter)
            return next_step(*args)
        self.app.tasks.planner.suggest = planner
        with self.as_user("alice"):
            task = self.app.task_start({"request":"排查 nginx 异常","autonomy":"read_only"})
            self.app.task_run({"task_id":task["task_id"]})
            self.assertTrue(entered.wait(2))
            self.app.task_stop({"task_id":task["task_id"]})
        release.set()
        self.assertEqual(self.wait(task["task_id"], {"stopped","blocked"})["runner_state"], "stopped")
        self.assertEqual(len(self.app.executor.list_operations()), 1)

    def test_healthy_service_does_not_satisfy_conditional_restart(self):
        self.app.tasks.planner.suggest = Mock(side_effect=[action("get_service_status",{"name":"nginx"}),action("restart_service",{"name":"nginx"},risk="high")])
        with self.as_user("alice"):
            task = self.app.task_start({"request":"先检查 nginx 状态，如果状态异常就重启 nginx","autonomy":"read_only"})
            self.app.task_run({"task_id":task["task_id"]})
        final = self.wait(task["task_id"], {"blocked","complete"})
        self.assertEqual(final["runner_state"], "blocked")
        self.assertEqual(len(self.app.executor.list_operations()), 1)
        self.assertEqual(self.app.approvals.list_public_records(), [])

    def test_account_disabled_during_planning_stops_next_step(self):
        entered, release = threading.Event(), threading.Event()
        first = True
        def planner(*args):
            nonlocal first
            if first:
                first=False; return action("get_service_status",{"name":"nginx"})
            entered.set(); release.wait(2)
            return action("read_log",{"path":"/var/log/nginx/error.log","lines":2})
        self.app.tasks.planner.suggest = planner
        with self.as_user("alice"):
            task = self.app.task_start({"request":"排查 nginx 异常","autonomy":"read_only"})
            self.app.task_run({"task_id":task["task_id"]})
        self.assertTrue(entered.wait(2))
        users = self.app.auth._users(); users["alice"]["enabled"] = False
        import json
        self.app.auth.path.write_text(json.dumps(users))
        release.set()
        record = self.app.tasks.tasks[task["task_id"]]
        for _ in range(100):
            if record["runner_state"] == "blocked":
                break
            time.sleep(.02)
        self.assertEqual(record["runner_state"], "blocked")
        self.assertEqual(len(self.app.executor.list_operations()), 1)
        with self.assertRaises(AuthenticationError):
            self.app.auth.principal("alice")


if __name__ == "__main__":
    unittest.main()
