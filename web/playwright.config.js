import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./browser",
  workers: 1,
  use: { baseURL: process.env.OIDC_TEST_URL || "http://localhost:8080" },
  timeout: 60000,
});
