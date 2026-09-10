import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  resolve: {
    alias: {
      '@shield/shared': resolve(__dirname, 'packages/shared/src'),
      '@shield/core': resolve(__dirname, 'packages/core/src'),
      '@shield/detection': resolve(__dirname, 'packages/detection/src'),
      '@shield/policy': resolve(__dirname, 'packages/policy/src'),
      '@shield/transformation': resolve(__dirname, 'packages/transformation/src'),
      '@shield/adapters': resolve(__dirname, 'packages/adapters/src'),
      '@shield/ui': resolve(__dirname, 'packages/ui/src'),
    },
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts', 'packages/**/*.test.ts', 'apps/**/*.test.ts'],
  },
});
