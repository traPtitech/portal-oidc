import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { derive, encodeSecret } from "../src/derive.js";

const baseURL = process.env.OIDC_TEST_URL || "http://localhost:8080";
const internalToken =
  process.env.OIDC_TEST_INTERNAL_TOKEN || "e2e-test-internal-token";
const callbackURL = "http://127.0.0.1:8080/callback";
const fixture = JSON.parse(
  readFileSync(new URL("../../development/provision.json", import.meta.url)),
);
const vector = JSON.parse(
  readFileSync(new URL("../test/vector.json", import.meta.url)),
);

// fetch does not keep cookies, so the test carries the session cookie itself.
function client() {
  const cookies = new Map();
  return async (path, init = {}) => {
    const headers = new Headers(init.headers);
    if (cookies.size > 0) {
      headers.set(
        "Cookie",
        [...cookies].map(([name, value]) => name + "=" + value).join("; "),
      );
    }
    const res = await fetch(new URL(path, baseURL), {
      ...init,
      headers,
      redirect: "manual",
    });
    for (const cookie of res.headers.getSetCookie()) {
      const pair = cookie.split(";")[0];
      const i = pair.indexOf("=");
      cookies.set(pair.slice(0, i), pair.slice(i + 1));
    }
    return res;
  };
}

function location(res) {
  return new URL(res.headers.get("Location"), baseURL);
}

test("the derived auth secret completes OIDC and the password is rejected", async (t) => {
  const send = client();
  const internal = { "X-Portal-Internal-Token": internalToken };
  const provision = await send("/internal/users/provision", {
    method: "POST",
    headers: { ...internal, "Content-Type": "application/json" },
    body: JSON.stringify(fixture),
  });
  assert.ok([200, 201].includes(provision.status), String(provision.status));
  const created = await send("/api/v1/admin/clients", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: "Login e2e test",
      client_type: "confidential",
      redirect_uris: [callbackURL],
    }),
  });
  assert.ok(created.ok, String(created.status));
  const rp = await created.json();
  t.after(() =>
    send("/api/v1/admin/clients/" + rp.client_id, { method: "DELETE" }),
  );

  const verifier = randomBytes(32).toString("base64url");
  const params = new URLSearchParams({
    client_id: rp.client_id,
    redirect_uri: callbackURL,
    response_type: "code",
    scope: "openid profile email",
    state: "e2e-test",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
  });
  const authorize = await send("/oauth2/authorize?" + params);
  assert.equal(authorize.status, 302);
  const loginURL = location(authorize);
  assert.equal(loginURL.pathname, "/login");
  const page = await send(loginURL);
  assert.equal(page.status, 200);
  const csrf = (await page.text()).match(
    /name="csrf_token" value="([^"]+)"/,
  )?.[1];
  assert.ok(csrf, "missing CSRF token");
  const login = (fields) =>
    send("/login", {
      method: "POST",
      body: new URLSearchParams({
        csrf_token: csrf,
        return_url: loginURL.searchParams.get("return_url"),
        ...fields,
      }),
    });

  const withPassword = await login({
    trapId: vector.trapId,
    password: vector.password,
  });
  assert.equal(withPassword.status, 401);

  const loggedIn = await login({
    trapId: vector.trapId,
    auth_secret: encodeSecret(derive(vector.trapId, vector.password)),
  });
  assert.equal(loggedIn.status, 302);
  const back = await send(location(loggedIn));
  assert.equal(back.status, 303);
  const callback = location(back);
  assert.equal(callback.origin + callback.pathname, callbackURL);
  assert.equal(callback.searchParams.get("state"), "e2e-test");

  const token = await send("/oauth2/token", {
    method: "POST",
    headers: {
      Authorization:
        "Basic " +
        Buffer.from(rp.client_id + ":" + rp.client_secret).toString("base64"),
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: callbackURL,
      code_verifier: verifier,
    }),
  });
  assert.equal(token.status, 200);
  const tokens = await token.json();
  const userinfo = () =>
    send("/oauth2/userinfo", {
      headers: { Authorization: "Bearer " + tokens.access_token },
    });
  const info = await userinfo();
  assert.equal(info.status, 200);
  const claims = await info.json();
  assert.equal(claims.sub, fixture.userId);
  assert.equal(claims.email, vector.email);
  assert.equal(claims.email_verified, false);
  assert.equal(claims.preferred_username, vector.trapId);

  const removed = await send("/internal/users/" + fixture.userId, {
    method: "DELETE",
    headers: internal,
  });
  assert.equal(removed.status, 204);
  assert.equal((await userinfo()).status, 401);
});
