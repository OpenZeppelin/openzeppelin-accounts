#!/usr/bin/env node

// Deletes the compiled JSON artifacts for any source that `src/package.json`'s
// `files` allowlist marks as ignored (e.g. mocks). Ported from
// `openzeppelin-contracts/scripts/remove-ignored-artifacts.js`, adjusted for
// the `packages/contracts` layout where the published package is rooted at
// `src/` (see `publishConfig.directory`) and the ignore patterns are
// therefore relative to `src/`.

const fs = require('fs');
const path = require('path');
const match = require('micromatch');

const readJSON = p => JSON.parse(fs.readFileSync(p));

// The published `files` allowlist lives in the inner (`src/`) package.json.
// Patterns there are relative to `src/`.
const pkgFiles = readJSON('src/package.json').files;

// `files` uses `!/…` for negations. Drop the `!` (micromatch takes plain
// patterns) and any leading `/` (npm anchors to package root; micromatch
// matches relative paths).
const ignorePatterns = pkgFiles.filter(pat => pat.startsWith('!')).map(pat => pat.slice(1).replace(/^\//, ''));

// A directory pattern like `mocks/**/*` matches the directory's children but
// not the directory itself. Add both so we catch either shape.
const ignorePatternsSubtrees = ignorePatterns.concat(ignorePatterns.map(pat => path.join(pat, '**/*')));

const artifactsDir = 'src/build/contracts';
const buildInfo = 'artifacts/build-info';

let removed = 0;
for (const filename of fs.readdirSync(buildInfo)) {
  const solcOutput = readJSON(path.join(buildInfo, filename)).output;
  for (const sourcePath in solcOutput.contracts) {
    // Solc output source paths are relative to hardhat's project root (i.e.
    // start with `src/…`). Strip that prefix so patterns from the inner
    // `files` array (which are relative to `src/`) match cleanly.
    const relative = sourcePath.replace(/^src\//, '');
    if (!match.any(relative, ignorePatternsSubtrees)) continue;
    for (const contract in solcOutput.contracts[sourcePath]) {
      const artifact = path.join(artifactsDir, contract + '.json');
      if (fs.existsSync(artifact)) {
        fs.unlinkSync(artifact);
        removed += 1;
      }
    }
  }
}

console.error(`Removed ${removed} ignored artifacts`);
