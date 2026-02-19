#!/usr/bin/env python3
"""Run an OpenID Connect conformance suite test plan."""

import argparse
import json
import os
import re
import sys
import time

import httpx

DEV_MODE = os.environ.get("CONFORMANCE_DEV_MODE", "0") == "1"


def create_api_client(base_url: str, token: str) -> httpx.Client:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(
        base_url=base_url,
        headers=headers,
        verify=not DEV_MODE,
        timeout=60.0,
    )


def create_browser_client() -> httpx.Client:
    return httpx.Client(
        verify=False,
        timeout=30.0,
    )


def create_test_plan(
    client: httpx.Client, plan_name: str, variant: dict | None, config: dict
) -> dict:
    params: dict[str, str] = {"planName": plan_name}
    if variant:
        params["variant"] = json.dumps(variant)
    resp = client.post(
        "/api/plan",
        params=params,
        json=config,
    )
    resp.raise_for_status()
    return resp.json()


def get_test_module_info(client: httpx.Client, module_id: str) -> dict:
    resp = client.get(f"/api/info/{module_id}")
    resp.raise_for_status()
    return resp.json()


def start_test_module(client: httpx.Client, plan_id: str, module_name: str) -> dict:
    resp = client.post(
        "/api/runner",
        params={"test": module_name, "plan": plan_id},
    )
    resp.raise_for_status()
    return resp.json()


def get_test_log(client: httpx.Client, module_id: str) -> list:
    resp = client.get(f"/api/log/{module_id}")
    resp.raise_for_status()
    return resp.json()


def find_authorize_url(log_entries: list) -> str | None:
    for entry in log_entries:
        url = entry.get("redirect_to_authorization_endpoint", "")
        if url:
            return url
    return None


def perform_browser_interaction(
    api_client: httpx.Client,
    browser: httpx.Client,
    module_id: str,
    oidc_server_url: str,
) -> None:
    log = get_test_log(api_client, module_id)
    auth_url = find_authorize_url(log)
    if not auth_url:
        return

    if oidc_server_url:
        auth_url = auth_url.replace("host.docker.internal:8080", oidc_server_url)

    print(f"  Browser: visiting authorize URL")
    try:
        resp = browser.get(auth_url, follow_redirects=False)
    except httpx.HTTPError as e:
        print(f"  Browser: authorize request failed: {e}")
        return

    if resp.status_code not in (301, 302, 303, 307, 308):
        print(f"  Browser: OP returned {resp.status_code} (no redirect)")
        return

    callback_url = resp.headers.get("location", "")
    if not callback_url:
        print(f"  Browser: redirect with no location header")
        return

    print(f"  Browser: following redirect to callback")
    try:
        cb_resp = browser.get(callback_url)
    except httpx.HTTPError as e:
        print(f"  Browser: callback request failed: {e}")
        return

    match = re.search(r"xhr\.open\('POST',\s*\"([^\"]+)\"", cb_resp.text)
    if not match:
        print("  Browser: no implicit submit URL found in callback page")
        return

    implicit_url = match.group(1).replace("\\/", "/")
    print(f"  Browser: submitting fragment to implicit endpoint")
    try:
        browser.post(implicit_url, content="", headers={"Content-Type": "text/plain"})
    except httpx.HTTPError as e:
        print(f"  Browser: implicit submit failed: {e}")


def wait_for_test(
    api_client: httpx.Client,
    browser: httpx.Client,
    module_id: str,
    oidc_server_url: str,
    timeout: int = 60,
) -> dict:
    start = time.time()
    browser_tried = False
    while time.time() - start < timeout:
        info = get_test_module_info(api_client, module_id)
        status = info.get("status", "UNKNOWN")
        if status in ("FINISHED", "INTERRUPTED"):
            return info
        if status == "WAITING" and not browser_tried:
            browser_tried = True
            perform_browser_interaction(
                api_client, browser, module_id, oidc_server_url
            )
        time.sleep(2)
    raise TimeoutError(f"Test {module_id} did not finish within {timeout}s")


def run_plan(
    api_client: httpx.Client,
    browser: httpx.Client,
    plan_name: str,
    variant: dict | None,
    config: dict,
    output_dir: str,
    oidc_server_url: str,
) -> bool:
    print(f"Creating test plan: {plan_name}")
    plan = create_test_plan(api_client, plan_name, variant, config)
    plan_id = plan["id"]
    modules = plan.get("modules", [])
    print(f"Plan ID: {plan_id}")
    print(f"Modules to run: {len(modules)}")

    all_passed = True
    results = []

    for module_entry in modules:
        module_name = module_entry["testModule"]
        print(f"\n--- Running: {module_name} ---")

        started = start_test_module(api_client, plan_id, module_name)
        module_id = started["id"]
        print(f"Module ID: {module_id}")

        try:
            info = wait_for_test(
                api_client, browser, module_id, oidc_server_url
            )
        except TimeoutError as e:
            print(f"TIMEOUT: {e}")
            all_passed = False
            results.append({"module": module_name, "result": "TIMEOUT"})
            continue

        result = info.get("result", "UNKNOWN")
        print(f"Result: {result}")

        log = get_test_log(api_client, module_id)
        log_path = os.path.join(output_dir, f"{module_name}.json")
        with open(log_path, "w") as f:
            json.dump(log, f, indent=2)

        results.append({"module": module_name, "result": result})

        if result not in ("PASSED", "WARNING", "REVIEW"):
            all_passed = False

    summary_path = os.path.join(output_dir, "summary.json")
    with open(summary_path, "w") as f:
        json.dump(
            {"plan_id": plan_id, "plan_name": plan_name, "results": results},
            f,
            indent=2,
        )

    print("\n=== Summary ===")
    for r in results:
        status_mark = "PASS" if r["result"] in ("PASSED", "WARNING", "REVIEW") else "FAIL"
        print(f"  [{status_mark}] {r['module']}: {r['result']}")

    return all_passed


def main() -> None:
    parser = argparse.ArgumentParser(description="Run OIDC conformance test plan")
    parser.add_argument("--server", required=True, help="Conformance suite base URL")
    parser.add_argument("--token", default="", help="API bearer token")
    parser.add_argument("--plan", required=True, help="Test plan name")
    parser.add_argument("--variant", default=None, help="Variant selection as JSON")
    parser.add_argument("--config", required=True, help="Path to test config JSON")
    parser.add_argument("--output", required=True, help="Output directory for results")
    parser.add_argument(
        "--oidc-server", default="",
        help="Local OIDC server host:port for URL rewriting (e.g., localhost:8080)",
    )
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    variant = json.loads(args.variant) if args.variant else None

    os.makedirs(args.output, exist_ok=True)

    api_client = create_api_client(args.server, args.token)
    browser = create_browser_client()

    try:
        passed = run_plan(
            api_client, browser, args.plan, variant, config, args.output,
            args.oidc_server,
        )
    finally:
        api_client.close()
        browser.close()

    if not passed:
        print("\nSome tests failed.")
        sys.exit(1)

    print("\nAll tests passed.")


if __name__ == "__main__":
    main()
