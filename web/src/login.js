const form = document.querySelector("form");
const button = form.querySelector("button");
const status = document.querySelector("#status");
button.disabled = false;
let busy = false;
form.addEventListener("submit", (event) => {
  event.preventDefault();
  if (busy || !form.reportValidity()) return;
  busy = true;
  button.disabled = true;
  status.textContent = "Signing in…";
  let worker;
  const fail = () => {
    worker?.terminate();
    busy = false;
    button.disabled = false;
    status.textContent = "Unable to sign in. Please try again.";
  };
  try {
    const email = form.elements.email.value.trim().toLowerCase();
    worker = new Worker("/login/assets/worker.js");
    worker.onerror = fail;
    worker.onmessage = ({ data }) => {
      worker.terminate();
      if (data.error) {
        fail();
        return;
      }
      form.elements.email.value = email;
      form.elements.auth_secret.value = data.secret;
      HTMLFormElement.prototype.submit.call(form);
    };
    const input = document.querySelector("#password");
    worker.postMessage({
      email,
      password: input.value,
      policy: JSON.parse(form.dataset.policy),
    });
    input.value = "";
  } catch {
    fail();
  }
});
