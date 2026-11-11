import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const html = readFileSync(
  new URL("../../internal/router/v1/loginassets/login.html", import.meta.url),
  "utf8",
);
const vector = JSON.parse(
  readFileSync(new URL("./vector.json", import.meta.url)),
);

// Runs src/login.js against the parts of the DOM and Worker API it uses.
let loads = 0;
async function loadPage() {
  const field = () => ({ value: "" });
  const elements = { trapId: field(), auth_secret: field() };
  const password = field();
  const button = { disabled: true };
  const status = { textContent: "" };
  const submitted = [];
  const workers = [];
  let onsubmit;
  const form = {
    elements,
    querySelector: () => button,
    addEventListener: (type, listener) => {
      if (type === "submit") onsubmit = listener;
    },
    reportValidity: () => true,
    submit: () =>
      submitted.push({
        trapId: elements.trapId.value,
        auth_secret: elements.auth_secret.value,
      }),
  };
  const nodes = { form, "#status": status, "#password": password };
  globalThis.document = { querySelector: (selector) => nodes[selector] };
  globalThis.Worker = class {
    constructor(url) {
      this.url = url;
      this.messages = [];
      this.terminated = false;
      workers.push(this);
    }
    postMessage(data) {
      this.messages.push(data);
    }
    terminate() {
      this.terminated = true;
    }
  };
  await import("../src/login.js?page=" + ++loads);
  return {
    elements,
    password,
    button,
    status,
    submitted,
    workers,
    submit: () => onsubmit({ preventDefault() {} }),
  };
}

test("the login page cannot submit a password without the script", () => {
  assert.doesNotMatch(html, /name="password"/);
  assert.doesNotMatch(html.match(/<input id="password"[^>]*>/)[0], /\bname=/);
  assert.match(html, /<button type="submit" disabled>/);
});

test("the login script submits the derived secret instead of the password", async () => {
  const page = await loadPage();
  assert.equal(page.button.disabled, false);
  page.elements.trapId.value = " " + vector.trapId + " ";
  page.password.value = vector.password;
  page.submit();
  assert.equal(page.status.textContent, "Signing in…");
  assert.equal(page.button.disabled, true);
  assert.equal(page.password.value, "");
  const [worker] = page.workers;
  assert.equal(worker.url, "/login/assets/worker.js");
  assert.deepEqual(worker.messages, [
    { trapId: vector.trapId, password: vector.password },
  ]);
  worker.onmessage({ data: { secret: vector.secret } });
  assert.equal(worker.terminated, true);
  assert.deepEqual(page.submitted, [
    { trapId: vector.trapId, auth_secret: vector.secret },
  ]);
});

for (const [name, fail] of [
  ["fails to load", (worker) => worker.onerror(new Event("error"))],
  ["reports an error", (worker) => worker.onmessage({ data: { error: true } })],
]) {
  test(`a worker that ${name} does not submit the login form`, async () => {
    const page = await loadPage();
    page.elements.trapId.value = vector.trapId;
    page.password.value = vector.password;
    page.submit();
    const [worker] = page.workers;
    fail(worker);
    assert.equal(worker.terminated, true);
    assert.equal(
      page.status.textContent,
      "Unable to sign in. Please try again.",
    );
    assert.equal(page.button.disabled, false);
    assert.equal(page.password.value, "");
    assert.deepEqual(page.submitted, []);
  });
}

test("the worker posts the secret that the server verifies", async () => {
  const posted = [];
  globalThis.self = { postMessage: (data) => posted.push(data) };
  await import("../src/worker.js");
  globalThis.self.onmessage({
    data: { trapId: vector.trapId, password: vector.password },
  });
  assert.deepEqual(posted, [{ secret: vector.secret }]);
});
