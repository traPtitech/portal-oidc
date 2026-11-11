import { derive, encodeSecret } from "./derive.js";
self.onmessage = ({ data }) => {
  try {
    const secret = derive(data.trapId, data.password);
    self.postMessage({ secret: encodeSecret(secret) });
  } catch {
    self.postMessage({ error: true });
  }
};
