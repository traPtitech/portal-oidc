import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_PATH = Path(__file__).with_name("run-test-plan.py")
SPEC = importlib.util.spec_from_file_location("run_test_plan", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
run_test_plan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(run_test_plan)


class BrowserContext:
    def __init__(self) -> None:
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.closed = True


class RunTestPlanTest(unittest.TestCase):
    def test_find_authorize_url_returns_latest_redirect(self) -> None:
        log = [
            {"redirect_to_authorization_endpoint": "https://op/first"},
            {"msg": "first callback completed"},
            {"redirect_to_authorization_endpoint": "https://op/second"},
        ]

        self.assertEqual(
            run_test_plan.find_authorize_url(log),
            "https://op/second",
        )

    def test_wait_for_test_drives_each_authorize_url_once(self) -> None:
        api_client = object()
        browser = object()
        statuses = [
            {"status": "WAITING"},
            {"status": "WAITING"},
            {"status": "WAITING"},
            {"status": "FINISHED", "result": "PASSED"},
        ]
        logs = [
            [{"redirect_to_authorization_endpoint": "https://op/first"}],
            [{"redirect_to_authorization_endpoint": "https://op/first"}],
            [
                {"redirect_to_authorization_endpoint": "https://op/first"},
                {"redirect_to_authorization_endpoint": "https://op/second"},
            ],
        ]

        with (
            mock.patch.object(
                run_test_plan, "get_test_module_info", side_effect=statuses
            ),
            mock.patch.object(run_test_plan, "get_test_log", side_effect=logs),
            mock.patch.object(
                run_test_plan, "perform_browser_interaction"
            ) as interact,
            mock.patch.object(run_test_plan.time, "sleep"),
        ):
            result = run_test_plan.wait_for_test(
                api_client, browser, "module-id", "localhost:8080"
            )

        self.assertEqual(result["result"], "PASSED")
        self.assertEqual(
            interact.call_args_list,
            [
                mock.call(
                    api_client,
                    browser,
                    "module-id",
                    "https://op/first",
                    "localhost:8080",
                ),
                mock.call(
                    api_client,
                    browser,
                    "module-id",
                    "https://op/second",
                    "localhost:8080",
                ),
            ],
        )

    def test_run_plan_isolates_browser_cookies_between_modules(self) -> None:
        first_browser = BrowserContext()
        second_browser = BrowserContext()
        plan = {
            "id": "plan-id",
            "modules": [
                {"testModule": "first-module"},
                {"testModule": "second-module"},
            ],
        }

        with (
            tempfile.TemporaryDirectory() as output_dir,
            mock.patch.object(run_test_plan, "create_test_plan", return_value=plan),
            mock.patch.object(
                run_test_plan,
                "start_test_module",
                side_effect=[{"id": "first-id"}, {"id": "second-id"}],
            ),
            mock.patch.object(
                run_test_plan,
                "create_browser_client",
                side_effect=[first_browser, second_browser],
            ),
            mock.patch.object(
                run_test_plan,
                "wait_for_test",
                side_effect=[
                    {"status": "FINISHED", "result": "PASSED"},
                    {"status": "FINISHED", "result": "PASSED"},
                ],
            ) as wait_for_test,
            mock.patch.object(run_test_plan, "get_test_log", return_value=[]),
        ):
            passed = run_test_plan.run_plan(
                object(),
                "plan-name",
                None,
                {},
                output_dir,
                "localhost:8080",
            )

        self.assertTrue(passed)
        self.assertIs(wait_for_test.call_args_list[0].args[1], first_browser)
        self.assertIs(wait_for_test.call_args_list[1].args[1], second_browser)
        self.assertTrue(first_browser.closed)
        self.assertTrue(second_browser.closed)

    def test_module_uses_suite_browser_only_for_configured_override(self) -> None:
        config = {
            "override": {
                "automated": {"browser": [{"match": "https://op/*"}]},
                "empty": {"browser": []},
            }
        }

        self.assertTrue(
            run_test_plan.module_uses_suite_browser(config, "automated")
        )
        self.assertFalse(run_test_plan.module_uses_suite_browser(config, "empty"))
        self.assertFalse(run_test_plan.module_uses_suite_browser(config, "missing"))


if __name__ == "__main__":
    unittest.main()
