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
    # SSL verification disabled: conformance suite uses self-signed certificates
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


TEST_USERNAME = os.environ.get("CONFORMANCE_TEST_USERNAME", "testuser")
TEST_PASSWORD = os.environ.get("CONFORMANCE_TEST_PASSWORD", "password")


def submit_login_form(
    browser: httpx.Client, login_url: str
) -> httpx.Response | None:
    """POST credentials to the login form and return the resulting redirect.

    The /login page on portal-oidc is a static HTML form whose action target is
    /login itself. After successful auth it issues a 302 back to the authorize
    URL embedded in the `return_url` hidden field.
    """
    parsed = httpx.URL(login_url)
    return_url = ""
    for key, value in parsed.params.multi_items():
        if key == "return_url":
            return_url = value
            break

    print("  Browser: submitting login credentials")
    try:
        return browser.post(
            login_url,
            data={
                "username": TEST_USERNAME,
                "password": TEST_PASSWORD,
                "return_url": return_url,
            },
            follow_redirects=False,
        )
    except httpx.HTTPError as e:
        print(f"  Browser: login submission failed: {e}")
        return None


def follow_authorize(
    browser: httpx.Client, auth_url: str, max_hops: int = 5
) -> httpx.Response | None:
    """Drive the authorize → (login →) callback redirect chain.

    Conformance tests that exercise prompt=login or max_age cause portal-oidc
    to redirect to /login even when there is an existing session, so we may
    bounce login → authorize → callback multiple times. Location headers may
    be relative URLs, so resolve them against the previous request URL on each
    hop.
    """
    current_url = httpx.URL(auth_url)
    for _ in range(max_hops):
        try:
            resp = browser.get(current_url, follow_redirects=False)
        except httpx.HTTPError as e:
            print(f"  Browser: request failed: {e}")
            return None

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if not location:
                return resp
            current_url = httpx.URL(location)
            if not current_url.host:
                current_url = resp.url.join(current_url)
            continue

        if resp.status_code == 200 and "/login" in str(resp.url):
            login_resp = submit_login_form(browser, str(resp.url))
            if not login_resp:
                return None
            if login_resp.status_code in (301, 302, 303, 307, 308):
                location = login_resp.headers.get("location", "")
                if not location:
                    return login_resp
                current_url = httpx.URL(location)
                if not current_url.host:
                    current_url = login_resp.url.join(current_url)
                continue
            # A successful login always answers with a redirect back to the
            # authorize URL; anything else (401 failure page, re-rendered
            # form) means the credentials were rejected.
            print(
                f"  Browser: login failed: status {login_resp.status_code}"
                f" at {login_resp.url}"
            )
            return None

        return resp

    print("  Browser: exceeded redirect hop limit")
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

    print("  Browser: visiting authorize URL")
    resp = follow_authorize(browser, auth_url)
    if resp is None:
        return

    # follow_authorize already drives the authorize → (login →) callback chain
    # all the way through, so resp is normally the 200 callback page served by
    # the conformance suite. If we somehow stopped at a 30x without following,
    # do one more GET to land on the callback page.
    if resp.status_code in (301, 302, 303, 307, 308):
        callback_url = resp.headers.get("location", "")
        if not callback_url:
            print("  Browser: redirect with no location header")
            return
        print("  Browser: following redirect to callback")
        try:
            resp = browser.get(callback_url)
        except httpx.HTTPError as e:
            print(f"  Browser: callback request failed: {e}")
            return

    if resp.status_code != 200:
        print(f"  Browser: OP returned {resp.status_code} (expected callback page)")
        return

    match = re.search(r"xhr\.open\('POST',\s*\"([^\"]+)\"", resp.text)
    if not match:
        # Some callback pages do not need a fragment submission step (e.g.
        # response_mode=query), so the auth code is already in the test's hands.
        return

    implicit_url = match.group(1).replace("\\/", "/")
    print("  Browser: submitting fragment to implicit endpoint")
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


def load_expected_skips(path: str | None) -> set[str]:
    if not path or not os.path.exists(path):
        return set()
    with open(path) as f:
        entries = json.load(f)
    return {e["test_module"] for e in entries}


def run_plan(
    api_client: httpx.Client,
    browser: httpx.Client,
    plan_name: str,
    variant: dict | None,
    config: dict,
    output_dir: str,
    oidc_server_url: str,
    expected_skips: set[str] | None = None,
) -> bool:
    print(f"Creating test plan: {plan_name}")
    plan = create_test_plan(api_client, plan_name, variant, config)
    plan_id = plan["id"]
    modules = plan.get("modules", [])
    print(f"Plan ID: {plan_id}")
    print(f"Modules to run: {len(modules)}")

    all_passed = True
    results = []

    skips = expected_skips or set()

    for module_entry in modules:
        module_name = module_entry["testModule"]
        if module_name in skips:
            print(f"\n--- Skipping: {module_name} (expected skip) ---")
            results.append({"module": module_name, "result": "SKIPPED"})
            continue
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

        if result not in ("PASSED", "WARNING", "REVIEW", "SKIPPED"):
            all_passed = False

    summary_path = os.path.join(output_dir, "summary.json")
    with open(summary_path, "w") as f:
        json.dump(
            {"plan_id": plan_id, "plan_name": plan_name, "results": results},
            f,
            indent=2,
        )

    print("\n=== Summary ===")
    passed_count = 0
    failed_count = 0
    skipped_count = 0
    for r in results:
        if r["result"] == "SKIPPED":
            status_mark = "SKIP"
            skipped_count += 1
        elif r["result"] in ("PASSED", "WARNING", "REVIEW"):
            status_mark = "PASS"
            passed_count += 1
        else:
            status_mark = "FAIL"
            failed_count += 1
        print(f"  [{status_mark}] {r['module']}: {r['result']}")

    total = len(results)
    print(f"\n  Total: {total}  Passed: {passed_count}  Failed: {failed_count}  Skipped: {skipped_count}")

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
    parser.add_argument(
        "--expected-skips", default=None,
        help="Path to JSON file listing test modules to skip",
    )
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    variant = json.loads(args.variant) if args.variant else None
    skips = load_expected_skips(args.expected_skips)

    os.makedirs(args.output, exist_ok=True)

    api_client = create_api_client(args.server, args.token)
    browser = create_browser_client()

    try:
        passed = run_plan(
            api_client, browser, args.plan, variant, config, args.output,
            args.oidc_server, skips,
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
