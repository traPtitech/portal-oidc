import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { sha256 } from "@noble/hashes/sha2.js";
import { derive, encodeSecret } from "../src/derive.js";
const v = JSON.parse(readFileSync(new URL("./vector.json", import.meta.url)));
test("policy v1 uses the case-sensitive traQ ID", () => {
  const secret = derive(" " + v.trapId + " ", v.password, v.policy);
  assert.equal(encodeSecret(secret), v.secret);
  assert.equal(encodeSecret(sha256(secret)), v.hash);
  assert.notEqual(
    encodeSecret(derive(v.trapId.toLowerCase(), v.password, v.policy)),
    v.secret,
  );
  assert.notEqual(
    encodeSecret(derive(v.trapId, " password", v.policy)),
    v.secret,
  );
});
test("email addresses and invalid identifiers cannot be used as KDF input", () => {
  for (const id of [
    v.email,
    "",
    "user name",
    "_user",
    "user_",
    "a".repeat(33),
    "あいう",
  ]) {
    assert.throws(() => derive(id, v.password, v.policy));
  }
});
test("unknown policy cannot silently downgrade", () => {
  assert.throws(() =>
    derive(v.trapId, v.password, { ...v.policy, version: 2 }),
  );
});
