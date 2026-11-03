import { argon2id } from "@noble/hashes/argon2.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
const utf8 = new TextEncoder();
export function derive(email, password, policy) {
  if (
    policy.kdf !== "argon2id" ||
    policy.version !== 1 ||
    policy.memoryKiB !== 65536 ||
    policy.iterations !== 3 ||
    policy.parallelism !== 4
  )
    throw new Error("Unsupported login policy");
  email = email.trim().toLowerCase();
  const pass = utf8.encode(password);
  const salt = sha256(utf8.encode("traPortal kdf v1:" + email));
  let root;
  try {
    root = argon2id(pass, salt, {
      m: policy.memoryKiB,
      t: policy.iterations,
      p: policy.parallelism,
      dkLen: 32,
    });
    return hkdf(sha256, root, undefined, utf8.encode("traPortal auth v1"), 32);
  } finally {
    pass.fill(0);
    root?.fill(0);
  }
}
export function encodeSecret(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}
