import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { sha256 } from "@noble/hashes/sha2.js";
import { derive, encodeSecret } from "../src/derive.js";
const v = JSON.parse(readFileSync(new URL("./vector.json", import.meta.url)));
test("policy v1 uses the case-sensitive traQ ID", () => {
  const secret = derive(v.trapId, v.password);
  assert.equal(encodeSecret(secret), v.secret);
  assert.equal(encodeSecret(sha256(secret)), v.hash);
  assert.notEqual(
    encodeSecret(derive(v.trapId.toLowerCase(), v.password)),
    v.secret,
  );
});
