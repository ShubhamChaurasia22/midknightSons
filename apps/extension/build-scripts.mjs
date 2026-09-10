import { build } from 'vite';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { unlinkSync, existsSync } from 'node:fs';

const __dirname = dirname(fileURLToPath(import.meta.url));

async function run() {
  // 1. Build background service worker (ES module format)
  await build({
    configFile: false,
    build: {
      outDir: resolve(__dirname, 'dist'),
      emptyOutDir: false,
      rollupOptions: {
        input: resolve(__dirname, 'src/background/index.ts'),
        output: {
          format: 'es',
          entryFileNames: 'background.js',
          inlineDynamicImports: true,
        },
      },
    },
  });

  // 2. Build content script (IIFE format - completely self-contained, no imports)
  await build({
    configFile: false,
    build: {
      outDir: resolve(__dirname, 'dist'),
      emptyOutDir: false,
      rollupOptions: {
        input: resolve(__dirname, 'src/content/index.ts'),
        output: {
          format: 'iife',
          name: 'ShieldContent',
          entryFileNames: 'content.js',
          inlineDynamicImports: true,
        },
      },
    },
  });

  // Remove any stale chunk file if present
  const files = ['dist/index-D6QojUl7.js'];
  for (const f of files) {
    const p = resolve(__dirname, f);
    if (existsSync(p)) {
      unlinkSync(p);
    }
  }
}

run().catch((err) => {
  console.error('Build scripts failed:', err);
  process.exit(1);
});
