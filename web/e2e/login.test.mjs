import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { derive, encodeSecret } from "../src/derive.js";
import { formData, parseInputs } from "../test/form.mjs";

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

// fetch does not keep cookies, so the test keeps them with the host, path
// and lifetime rules of RFC 6265 §5.2 to §5.4 that a browser applies.
function parseCookie(line, url) {
  const [pair, ...attrs] = line.split(";").map((part) => part.trim());
  const i = pair.indexOf("=");
  const dir = url.pathname.slice(0, url.pathname.lastIndexOf("/"));
  const cookie = {
    name: pair.slice(0, i),
    value: pair.slice(i + 1),
    host: url.hostname,
    path: dir || "/",
    expires: Infinity,
  };
  let maxAge;
  for (const attr of attrs) {
    const j = attr.indexOf("=");
    const key = (j < 0 ? attr : attr.slice(0, j)).toLowerCase();
    const value = j < 0 ? "" : attr.slice(j + 1);
    if (key === "path" && value.startsWith("/")) cookie.path = value;
    if (key === "expires") cookie.expires = Date.parse(value);
    if (key === "max-age") maxAge = Number(value);
    // Domain cookies would also reach subdomains, which this test never uses.
    if (key === "domain" && value.replace(/^\./, "") !== url.hostname) {
      return undefined;
    }
  }
  if (maxAge !== undefined) cookie.expires = Date.now() + maxAge * 1000;
  return cookie;
}

function pathMatches(cookiePath, path) {
  return (
    path === cookiePath ||
    path.startsWith(cookiePath.endsWith("/") ? cookiePath : cookiePath + "/")
  );
}

function client() {
  const jar = new Map();
  return async (path, init = {}) => {
    const url = new URL(path, baseURL);
    const headers = new Headers(init.headers);
    const cookies = [...jar.values()].filter(
      (c) =>
        c.expires > Date.now() &&
        c.host === url.hostname &&
        pathMatches(c.path, url.pathname),
    );
    if (cookies.length > 0) {
      headers.set(
        "Cookie",
        cookies.map((c) => c.name + "=" + c.value).join("; "),
      );
    }
    const res = await fetch(url, { ...init, headers, redirect: "manual" });
    for (const line of res.headers.getSetCookie()) {
      const cookie = parseCookie(line, url);
      if (cookie) jar.set(cookie.name + ";" + cookie.path, cookie);
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
  // The login script fills trapId and auth_secret and leaves the other
  // fields of the rendered form as they are.
  const form = formData(parseInputs(await page.text()));
  assert.ok(form.csrf_token, "missing CSRF token");
  assert.equal(form.return_url, loginURL.searchParams.get("return_url"));
  const login = (fields) =>
    send("/login", {
      method: "POST",
      body: new URLSearchParams({ ...form, ...fields }),
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
