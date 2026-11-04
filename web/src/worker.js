import { derive, encodeSecret } from "./derive.js";
self.onmessage = ({ data }) => {
  let secret;
  try {
    secret = derive(data.trapId, data.password, data.policy);
    self.postMessage({ secret: encodeSecret(secret) });
  } catch {
    self.postMessage({ error: true });
  } finally {
    secret?.fill(0);
    data.password = "";
  }
};
