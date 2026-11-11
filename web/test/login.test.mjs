import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { formData, parseInputs } from "./form.mjs";

const html = readFileSync(
  new URL("../../internal/router/v1/loginassets/login.html", import.meta.url),
  "utf8",
);
const vector = JSON.parse(
  readFileSync(new URL("./vector.json", import.meta.url)),
);

// Runs src/login.js against the inputs of login.html and the parts of the DOM
// and Worker API that it uses. A submission records every input with a name,
// as the browser would send it.
let loads = 0;
async function loadPage() {
  const inputs = parseInputs(html).map(({ id, name, value }) => ({
    id,
    name,
    value: value ?? "",
  }));
  const elements = {};
  for (const input of inputs) {
    if (input.id) elements[input.id] = input;
    if (input.name) elements[input.name] = input;
  }
  const button = { disabled: true };
  const status = { textContent: "" };
  const submitted = [];
  const workers = [];
  let onsubmit;
  const post = () => submitted.push(formData(inputs));
  const form = {
    elements,
    querySelector: () => button,
    addEventListener: (type, listener) => {
      if (type === "submit") onsubmit = listener;
    },
    reportValidity: () => true,
    submit: post,
  };
  const nodes = { form, "#status": status, "#password": elements.password };
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
    password: elements.password,
    button,
    status,
    submitted,
    workers,
    // The browser submits the form itself unless the listener cancels it.
    submit: () => {
      let cancelled = false;
      onsubmit({
        preventDefault: () => {
          cancelled = true;
        },
      });
      if (!cancelled) post();
    },
  };
}

test("the login page cannot submit a password without the script", () => {
  const password = parseInputs(html).find((input) => input.type === "password");
  assert.equal(password.name, undefined);
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
    {
      trapId: vector.trapId,
      auth_secret: vector.secret,
      return_url: "{{.ReturnURL}}",
      csrf_token: "{{.CSRF}}",
    },
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
