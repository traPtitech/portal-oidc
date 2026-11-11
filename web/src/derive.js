const utf8 = new TextEncoder();
// Policy v1. The server accepts only verifiers that use these parameters.
export async function derive(trapId, password) {
  const salt = await crypto.subtle.digest(
    "SHA-256",
    utf8.encode("traPortal kdf v1:" + trapId),
  );
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    utf8.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const root = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 100000 },
    passwordKey,
    256,
  );
  const rootKey = await crypto.subtle.importKey("raw", root, "HKDF", false, [
    "deriveBits",
  ]);
  const secret = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(),
      info: utf8.encode("traPortal auth v1"),
    },
    rootKey,
    256,
  );
  return new Uint8Array(secret);
}
export function encodeSecret(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}
