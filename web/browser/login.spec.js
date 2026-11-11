import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
const callbackURL = "http://127.0.0.1:8080/callback";
const fixture = JSON.parse(
  readFileSync(new URL("../../development/provision.json", import.meta.url)),
);
const vector = JSON.parse(
  readFileSync(new URL("../test/vector.json", import.meta.url)),
);
test("browser derives secret and completes OIDC without sending its password", async ({
  page,
  request,
}) => {
  const provision = await request.post("/internal/users/provision", {
    headers: {
      "X-Portal-Internal-Token":
        process.env.OIDC_TEST_INTERNAL_TOKEN || "browser-test-internal-token",
    },
    data: fixture,
  });
  expect([200, 201]).toContain(provision.status());
  const created = await request.post("/api/v1/admin/clients", {
    data: {
      name: "Browser login test",
      client_type: "confidential",
      redirect_uris: [callbackURL],
    },
  });
  expect(created.ok()).toBeTruthy();
  const client = await created.json();
  const verifier = randomBytes(32).toString("base64url");
  const params = new URLSearchParams({
    client_id: client.client_id,
    redirect_uri: callbackURL,
    response_type: "code",
    scope: "openid profile email",
    state: "browser-test",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
  });
  const sends = [];
  page.on("request", (r) => {
    if (r.method() === "POST") sends.push(r);
  });
  await page.goto("/oauth2/authorize?" + params);
  await page.getByLabel("traQ ID").fill(" " + vector.trapId + " ");
  await page.getByLabel("Password").fill(vector.password);
  await page.getByRole("button", { name: "Login", exact: true }).click();
  await page.waitForURL("**/callback?**");
  const callback = new URL(page.url());
  expect(callback.searchParams.get("state")).toBe("browser-test");
  const login = sends.find((r) => new URL(r.url()).pathname === "/login");
  expect(login).toBeTruthy();
  const sent = new URLSearchParams(login.postData());
  expect(sent.has("password")).toBe(false);
  expect(sent.get("auth_secret")).toBe(vector.secret);
  expect(sent.get("trapId")).toBe(vector.trapId);
  expect(sent.has("email")).toBe(false);
  expect(sends.every((r) => !r.postData()?.includes("password="))).toBe(true);
  const token = await request.post("/oauth2/token", {
    headers: {
      Authorization:
        "Basic " +
        Buffer.from(client.client_id + ":" + client.client_secret).toString(
          "base64",
        ),
    },
    form: {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: callbackURL,
      code_verifier: verifier,
    },
  });
  expect(token.status()).toBe(200);
  const tokens = await token.json();
  const info = await request.get("/oauth2/userinfo", {
    headers: { Authorization: "Bearer " + tokens.access_token },
  });
  expect(info.status()).toBe(200);
  expect(await info.json()).toMatchObject({
    sub: fixture.userId,
    email: vector.email,
    email_verified: false,
    preferred_username: vector.trapId,
  });
  const removed = await request.delete("/internal/users/" + fixture.userId, {
    headers: {
      "X-Portal-Internal-Token":
        process.env.OIDC_TEST_INTERNAL_TOKEN || "browser-test-internal-token",
    },
  });
  expect(removed.status()).toBe(204);
  const revokedInfo = await request.get("/oauth2/userinfo", {
    headers: { Authorization: "Bearer " + tokens.access_token },
  });
  expect(revokedInfo.status()).toBe(401);
  await page.goto("/login");
  expect(
    await page.evaluate(() => localStorage.length + sessionStorage.length),
  ).toBe(0);
  await request.delete("/api/v1/admin/clients/" + client.client_id);
});
test("a missing script never submits a password", async ({
  browser,
  baseURL,
}) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  const page = await context.newPage();
  await page.goto(baseURL + "/login");
  await expect(
    page.getByRole("button", { name: "Login", exact: true }),
  ).toBeDisabled();
  expect(await page.locator('input[name="password"]').count()).toBe(0);
  await context.close();
});
