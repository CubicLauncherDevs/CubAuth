import { defineConfig } from 'vitest/config';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';

export default defineConfig({
  plugins: [
    cloudflareTest(async () => ({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        compatibilityDate: '2026-08-15',
        bindings: { TEST_MIGRATIONS: await readD1Migrations('./migrations') },
      },
    })),
  ],
  test: { include: ['test/worker.test.ts'], testTimeout: 15000 },
});
