import { fileURLToPath } from 'node:url';
import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import { includeIgnoreFile } from '@eslint/compat';
import eslintConfigPrettier from 'eslint-config-prettier/flat';
import { defineConfig, globalIgnores } from 'eslint/config';
import nextVitals from 'eslint-config-next/core-web-vitals'
import nextTypescript from 'eslint-config-next/typescript'

const gitignorePath = fileURLToPath(new URL('.gitignore', import.meta.url));

export default defineConfig([
  includeIgnoreFile(gitignorePath),
  globalIgnores([
    'packages/contracts/artifacts',
    'lib',
    'packages/docs/.next/**',
    'packages/docs/out/**',
    'packages/docs/build/**',
    'packages/docs/.source/**',
    'packages/docs/next-env.d.ts',
    "packages/docs/postcss.config.mjs"
  ]),
  { files: ['**/*.{js,mjs,cjs,ts}'], plugins: { js }, extends: ['js/recommended'] },
  { files: ['**/*.js'], languageOptions: { sourceType: 'commonjs' } },
  { files: ['**/*.{js,mjs,cjs,ts}'], languageOptions: { globals: { ...globals.browser, ...globals.mocha, ...globals.node } } },
  { extends: [tseslint.configs.recommended], ignores: ['packages/contracts/**/*.js', 'lib'] },
  js.configs.recommended,
  eslintConfigPrettier,
  eslintPluginPrettierRecommended,
  {
    // Next.js config for packages/docs
    files: ['packages/docs/**/*.{js,mjs,cjs,ts,tsx,jsx}'],
    extends: [nextVitals, nextTypescript],
    rules: {
      '@next/next/no-html-link-for-pages': ['error', 'packages/docs']
    },
    settings: {
      next: {
        rootDir: '.',
      },
    },
  },
]);
