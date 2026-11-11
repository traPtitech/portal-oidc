import { argon2id } from "@noble/hashes/argon2.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
const utf8 = new TextEncoder();
// Policy v1. The server accepts only verifiers that use these parameters.
export function derive(trapId, password) {
  const salt = sha256(utf8.encode("traPortal kdf v1:" + trapId));
  const root = argon2id(utf8.encode(password), salt, {
    m: 65536,
    t: 3,
    p: 4,
    dkLen: 32,
  });
  return hkdf(sha256, root, undefined, utf8.encode("traPortal auth v1"), 32);
}
export function encodeSecret(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}
