import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';

export default defineConfig({
  plugins: [cloudflareTest({
    wrangler: { configPath: './wrangler.jsonc' },
    miniflare: { compatibilityDate: '2026-08-15' },
  })],
  test: { include: ['test/worker.test.ts'], testTimeout: 15000 },
});
