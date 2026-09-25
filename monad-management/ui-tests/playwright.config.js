import {defineConfig} from "@playwright/test";
export default defineConfig({testDir: ".", testMatch: "*.spec.js", workers: 1,
  timeout: 60000, use: {browserName: "chromium", headless: true}});
