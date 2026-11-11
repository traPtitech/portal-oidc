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
// that it uses. Node provides the same Web Crypto API as the browser. A
// submission records every input with a name, as the browser would send it.
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
  await import("../src/login.js?page=" + ++loads);
  return {
    elements,
    password: elements.password,
    button,
    status,
    submitted,
    // The browser submits the form itself unless the listener cancels it
    // before its first await. The returned promise settles with the listener.
    submit: () => {
      let cancelled = false;
      const done = onsubmit({
        preventDefault: () => {
          cancelled = true;
        },
      });
      if (!cancelled) post();
      return done;
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
  const done = page.submit();
  assert.equal(page.status.textContent, "Signing in…");
  assert.equal(page.button.disabled, true);
  assert.equal(page.password.value, "");
  await done;
  assert.deepEqual(page.submitted, [
    {
      trapId: vector.trapId,
      auth_secret: vector.secret,
      return_url: "{{.ReturnURL}}",
      csrf_token: "{{.CSRF}}",
    },
  ]);
});

test("a failed derivation does not submit the login form", async (t) => {
  t.mock.method(crypto.subtle, "deriveBits", async () => {
    throw new Error("unavailable");
  });
  const page = await loadPage();
  page.elements.trapId.value = vector.trapId;
  page.password.value = vector.password;
  await page.submit();
  assert.equal(page.status.textContent, "Unable to sign in. Please try again.");
  assert.equal(page.button.disabled, false);
  assert.equal(page.password.value, "");
  assert.deepEqual(page.submitted, []);
});
