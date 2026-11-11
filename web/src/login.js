import { derive, encodeSecret } from "./derive.js";
const form = document.querySelector("form");
const button = form.querySelector("button");
const status = document.querySelector("#status");
button.disabled = false;
let busy = false;
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy || !form.reportValidity()) return;
  busy = true;
  button.disabled = true;
  status.textContent = "Signing in…";
  const input = document.querySelector("#password");
  const password = input.value;
  input.value = "";
  try {
    const trapId = form.elements.trapId.value.trim();
    const secret = await derive(trapId, password);
    form.elements.trapId.value = trapId;
    form.elements.auth_secret.value = encodeSecret(secret);
    form.submit();
  } catch {
    busy = false;
    button.disabled = false;
    status.textContent = "Unable to sign in. Please try again.";
  }
});
