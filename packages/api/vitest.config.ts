import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    // Integration tests need a live Postgres and are excluded from the default
    // `npm test` run; `npm run test:integration` targets them explicitly.
    exclude: ["node_modules", "dist"],
    globals: false,
  },
});
