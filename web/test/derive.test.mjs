import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { derive, encodeSecret } from "../src/derive.js";
const v = JSON.parse(readFileSync(new URL("./vector.json", import.meta.url)));
test("policy v1 uses the case-sensitive traQ ID", async () => {
  const secret = await derive(v.trapId, v.password);
  assert.equal(encodeSecret(secret), v.secret);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", secret));
  assert.equal(encodeSecret(hash), v.hash);
  assert.notEqual(
    encodeSecret(await derive(v.trapId.toLowerCase(), v.password)),
    v.secret,
  );
});
