#!/usr/bin/env node
/**
 * Sync SDK artifacts from Foundry output into TypeScript files under `packages/sdk/src/artifacts/`.
 * Each generated file exports an `XArtifact` object shaped like the Foundry JSON callers used
 * to import — `{ abi, bytecode: { object } }` — so replacing a JSON import is a one-line diff.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Every artifact the SDK imports. `source` is the Foundry artifact relative to the repo root;
 * `output` is where the generated TS lands; `exportName` is the identifier callers import.
 */
const CONTRACTS = [
  {
    source: 'packages/contracts/out/OpenAccountFactory.sol/OpenAccountFactory.json',
    output: 'packages/sdk/src/artifacts/OpenAccountFactory.ts',
    exportName: 'OpenAccountFactoryArtifact',
  },
  {
    source: 'packages/contracts/out/ERC7579ECDSAValidator.sol/ERC7579ECDSAValidator.json',
    output: 'packages/sdk/src/artifacts/ERC7579ECDSAValidator.ts',
    exportName: 'ECDSAValidatorArtifact',
  },
  {
    source: 'packages/contracts/out/ERC7579WebAuthnValidator.sol/ERC7579WebAuthnValidator.json',
    output: 'packages/sdk/src/artifacts/ERC7579WebAuthnValidator.ts',
    exportName: 'WebAuthnValidatorArtifact',
  },
  {
    source: 'packages/contracts/out/ERC7579MultisigValidator.sol/ERC7579MultisigValidator.json',
    output: 'packages/sdk/src/artifacts/ERC7579MultisigValidator.ts',
    exportName: 'ERC7579MultisigValidatorArtifact',
  },
  {
    source: 'packages/contracts/out/IERC1271.sol/IERC1271.json',
    output: 'packages/sdk/src/artifacts/IERC1271.ts',
    exportName: 'IERC1271Artifact',
  },
  {
    source: 'packages/contracts/out/CrossChainAppMock.sol/CrossChainAppMock.json',
    output: 'packages/sdk/src/artifacts/CrossChainAppMock.ts',
    exportName: 'CrossChainAppMockArtifact',
  },
  {
    source: 'packages/contracts/out/ERC7913CrossChainAppMock.sol/ERC7913CrossChainAppMock.json',
    output: 'packages/sdk/src/artifacts/ERC7913CrossChainAppMock.ts',
    exportName: 'ERC7913CrossChainAppMockArtifact',
  },
];

const HEADER = source => `// AUTO-GENERATED — do not edit. Rewritten from the Foundry artifact by scripts/sync-artifact.mjs
// on every install (postinstall) and by CI. Commit changes to this file when the underlying
// contract changes; CI fails the build if the committed copy drifts from the artifact.
// Source: ${source}
`;

const loadPrettier = async () => {
  try {
    const prettier = await import('prettier');
    const config = (await prettier.resolveConfig(ROOT)) ?? {};
    return source => prettier.format(source, { parser: 'typescript', ...config });
  } catch {
    // Fallback, another CI job will catch it.
    return source => Promise.resolve(source);
  }
};

const emitOne = async ({ source, output, exportName }, format) => {
  const absSource = join(ROOT, source);
  const absOutput = join(ROOT, output);

  if (!existsSync(absSource)) {
    console.log(`sync-artifact: skip ${output} (source ${source} not built)`);
    return { output, skipped: true };
  }

  const artifact = JSON.parse(readFileSync(absSource, 'utf8'));
  if (!Array.isArray(artifact.abi)) {
    throw new Error(`sync-artifact: ${source} has no .abi array`);
  }

  // Preserve just the fields the SDK reads (`.abi`, `.bytecode.object`) rather than mirroring
  // the whole Foundry JSON. Interfaces have an empty `bytecode.object` ("0x"); keep it so the
  // shape is uniform and the field always exists.
  const bytecodeObject = artifact.bytecode?.object ?? '0x';
  const value = { abi: artifact.abi, bytecode: { object: bytecodeObject } };

  const body = `${HEADER(source)}\nexport const ${exportName} = ${JSON.stringify(value)} as const;\n`;
  const formatted = await format(body);

  mkdirSync(dirname(absOutput), { recursive: true });
  writeFileSync(absOutput, formatted);
  console.log(`sync-artifact: wrote ${output}`);
  return { output, skipped: false };
};

const format = await loadPrettier();
const results = await Promise.all(CONTRACTS.map(entry => emitOne(entry, format)));

// A full skip (fresh clone, contracts not built) is fine — the committed abi/ files stand
// in as the last-known state until `forge build` runs. A partial update leaves the tree in
// an inconsistent state, so surface it as an error rather than a silent partial success.
const emitted = results.filter(r => !r.skipped).length;
const skipped = results.length - emitted;
if (emitted > 0 && skipped > 0) {
  console.error(`sync-artifact: partial update — ${emitted} emitted, ${skipped} skipped. Rebuild all contracts and re-run.`);
  process.exit(1);
}

// Best-effort: format every generated file through the workspace's prettier config so the output
// matches what `format:check` expects. If prettier isn't available (fallback branch above), the
// files are left as-is and format:check will flag them.
const emittedPaths = results.filter(r => !r.skipped).map(r => join(ROOT, r.output));
if (emittedPaths.length > 0) {
  try {
    execFileSync(
      'node_modules/.bin/prettier',
      ['--log-level', 'error', '--write', ...emittedPaths.map(p => relative(ROOT, p))],
      {
        cwd: ROOT,
        stdio: 'inherit',
      },
    );
  } catch {
    // Non-fatal: the in-memory format above already ran. This is a defence-in-depth pass for the
    // rare case where prettier's config was applied differently at load time vs CLI time.
  }
}
