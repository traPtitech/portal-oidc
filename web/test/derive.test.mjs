import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { sha256 } from "@noble/hashes/sha2.js";
import { derive, encodeSecret } from "../src/derive.js";
const v = JSON.parse(readFileSync(new URL("./vector.json", import.meta.url)));
test("Portal policy v1 golden vector and email normalization", () => {
  const secret = derive(" TestUser@EXAMPLE.TEST ", v.password, v.policy);
  assert.equal(encodeSecret(secret), v.secret);
  assert.equal(encodeSecret(sha256(secret)), v.hash);
  assert.notEqual(
    encodeSecret(derive(v.email, " password", v.policy)),
    v.secret,
  );
});
test("unknown policy cannot silently downgrade", () => {
  assert.throws(() => derive(v.email, v.password, { ...v.policy, version: 2 }));
});
